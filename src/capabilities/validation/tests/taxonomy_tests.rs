use crate::capabilities::validation::taxonomy::{
    MAX_TRAITS_PER_DIRECTORY, ObjectivesWellknownViolation, find_cap_obj_violations,
    find_cap_wellknown_violations, find_deep_taxonomy_directories, find_fragmented_sibling_cohorts,
    find_metadata_cross_tier_refs, find_objectives_wellknown_violations,
    find_oversized_trait_directories, find_sparse_sibling_cohorts,
    find_suppression_only_building_blocks, find_wellknown_baseline_rules,
    find_wellknown_high_criticality_basenames, find_wellknown_missing_section_filter,
    find_wellknown_missing_size_filter,
};
use crate::composite_rules::traits::CompositeTrait;
use crate::composite_rules::{Arch, Condition, FileType, PathQuery, Platform, TraitDefinition};
use crate::types::Criticality;
use std::collections::HashMap;
use std::path::PathBuf;

fn make_trait(id: &str, ref_id: &str) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Trait {
            id: ref_id.to_string(),
        },
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

fn make_composite(id: &str, all_refs: &[&str]) -> CompositeTrait {
    CompositeTrait {
        required_trait_indices: Vec::new(),
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(
            all_refs
                .iter()
                .map(|r| Condition::Trait { id: r.to_string() })
                .collect(),
        ),
        any: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

fn make_composite_suspicious(id: &str, all_refs: &[&str]) -> CompositeTrait {
    CompositeTrait {
        required_trait_indices: Vec::new(),
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(
            all_refs
                .iter()
                .map(|r| Condition::Trait { id: r.to_string() })
                .collect(),
        ),
        any: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

// ---- hostile composites must reference two notable+ legs ----

#[test]
fn test_hostile_with_too_few_notable_legs() {
    use crate::capabilities::validation::find_hostile_composites_with_too_few_notable_legs;

    fn leaf(id: &str, crit: Criticality) -> TraitDefinition {
        TraitDefinition {
            crit,
            ..make_trait(id, "ignored")
        }
    }
    let traits = vec![
        leaf("objectives/x::a", Criticality::Component),
        leaf("objectives/x::b", Criticality::Component),
        leaf("objectives/x::notable-leg", Criticality::Notable),
        leaf("objectives/x::notable-leg-2", Criticality::Notable),
        // notable traits reachable only via a directory-subtree reference
        leaf("micro-behaviors/comms/http::client", Criticality::Notable),
        leaf("micro-behaviors/comms/http::request", Criticality::Notable),
    ];

    let mut all_component =
        make_composite("objectives/x::bad", &["objectives/x::a", "objectives/x::b"]);
    all_component.crit = Criticality::Hostile;

    let mut direct_notable = make_composite(
        "objectives/x::good-direct",
        &[
            "objectives/x::a",
            "objectives/x::notable-leg",
            "objectives/x::notable-leg-2",
        ],
    );
    direct_notable.crit = Criticality::Hostile;

    // directory reference into a subtree containing a notable trait
    let mut dir_ref = make_composite("objectives/x::good-dir", &["micro-behaviors/comms/http"]);
    dir_ref.crit = Criticality::Hostile;

    // transitive: hostile -> component sub-composite -> two notable legs
    let sub = make_composite(
        "objectives/x::sub",
        &["objectives/x::notable-leg", "objectives/x::notable-leg-2"],
    ); // Baseline
    let mut transitive = make_composite("objectives/x::good-transitive", &["objectives/x::sub"]);
    transitive.crit = Criticality::Hostile;

    // non-hostile composites are ignored even with only component legs
    let non_hostile = make_composite("objectives/x::ignored", &["objectives/x::a"]);

    let composites = vec![
        all_component,
        direct_notable,
        dir_ref,
        sub,
        transitive,
        non_hostile,
    ];
    let v = find_hostile_composites_with_too_few_notable_legs(&traits, &composites);
    assert_eq!(v, vec!["objectives/x::bad".to_string()]);
}

// ---- metadata cross-tier refs ----

#[test]
fn test_metadata_referencing_cap_is_violation() {
    let traits = vec![make_trait(
        "metadata/format/suspicious",
        "micro-behaviors/crypto/aes",
    )];
    let composites = vec![];
    let sources = HashMap::new();
    let v = find_metadata_cross_tier_refs(&traits, &composites, &sources);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].1, "micro-behaviors/crypto/aes");
}

#[test]
fn test_metadata_referencing_objectives_is_violation() {
    let composites = vec![make_composite(
        "metadata/format/bad",
        &["objectives/impact/encrypt"],
    )];
    let sources = HashMap::new();
    let v = find_metadata_cross_tier_refs(&[], &composites, &sources);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].1, "objectives/impact/encrypt");
}

#[test]
fn test_metadata_referencing_wellknown_is_violation() {
    let composites = vec![make_composite(
        "metadata/format/bad",
        &["well-known/malware/emotet/loader"],
    )];
    let sources = HashMap::new();
    let v = find_metadata_cross_tier_refs(&[], &composites, &sources);
    assert_eq!(v.len(), 1);
}

#[test]
fn test_metadata_referencing_wellknown_non_malware_is_also_violation() {
    let composites = vec![make_composite(
        "metadata/format/composite",
        &[
            "well-known/tool/cobalt-strike/beacon",
            "well-known/lib/openssl/v3",
            "well-known/app/chrome/extension",
        ],
    )];
    let sources = HashMap::new();
    let v = find_metadata_cross_tier_refs(&[], &composites, &sources);
    assert_eq!(
        v.len(),
        3,
        "metadata/ must not reference any well-known/ subtree"
    );
}

#[test]
fn test_metadata_referencing_metadata_is_ok() {
    let traits = vec![make_trait(
        "metadata/format/composite",
        "metadata/format/elf",
    )];
    let composites = vec![make_composite(
        "metadata/quality/check",
        &["metadata/format/elf", "metadata/language/go"],
    )];
    let sources = HashMap::new();
    let v = find_metadata_cross_tier_refs(&traits, &composites, &sources);
    assert!(v.is_empty(), "metadata → metadata should be allowed");
}

// ---- micro-behaviors → well-known ----

#[test]
fn test_cap_referencing_wellknown_malware_is_violation() {
    let traits = vec![make_trait(
        "micro-behaviors/crypto/known-malware",
        "well-known/malware/emotet/loader",
    )];
    let sources = HashMap::new();
    let v = find_cap_wellknown_violations(&traits, &[], &sources);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].1, "well-known/malware/emotet/loader");
}

#[test]
fn test_cap_composite_referencing_wellknown_non_malware_is_also_violation() {
    let composites = vec![make_composite_suspicious(
        "micro-behaviors/net/suspicious",
        &[
            "micro-behaviors/net/http-post",
            "well-known/tool/cobalt-strike/beacon",
        ],
    )];
    let sources = HashMap::new();
    let v = find_cap_wellknown_violations(&[], &composites, &sources);
    assert_eq!(
        v.len(),
        1,
        "micro-behaviors/ may not reference any well-known/ subtree"
    );
}

#[test]
fn test_cap_referencing_cap_and_metadata_is_ok() {
    let traits = vec![make_trait(
        "micro-behaviors/crypto/aes",
        "micro-behaviors/crypto/symmetric",
    )];
    let composites = vec![make_composite(
        "micro-behaviors/net/http",
        &["micro-behaviors/net/socket", "metadata/format/elf"],
    )];
    let sources = HashMap::new();
    let v = find_cap_wellknown_violations(&traits, &composites, &sources);
    assert!(
        v.is_empty(),
        "cap → cap and cap → metadata should be allowed"
    );
}

// ---- existing: micro-behaviors → objectives ----

#[test]
fn test_cap_referencing_objectives_is_violation() {
    let traits = vec![make_trait(
        "micro-behaviors/process/shell",
        "objectives/execution/reverse-shell",
    )];
    let sources = HashMap::new();
    let v = find_cap_obj_violations(&traits, &[], &sources);
    assert_eq!(v.len(), 1);
}

#[test]
fn test_objectives_referencing_cap_is_ok() {
    let composites = vec![make_composite(
        "objectives/c2/reverse-shell",
        &["micro-behaviors/net/socket", "micro-behaviors/process/exec"],
    )];
    let sources = HashMap::new();
    let v = find_cap_obj_violations(&[], &composites, &sources);
    assert!(
        v.is_empty(),
        "objectives → cap is the normal direction and should be allowed"
    );
}

// ---- objectives/ → well-known/ ----

fn make_composite_with_unless(id: &str, all_refs: &[&str], unless_refs: &[&str]) -> CompositeTrait {
    let mut c = make_composite(id, all_refs);
    c.unless = Some(
        unless_refs
            .iter()
            .map(|r| Condition::Trait { id: r.to_string() })
            .collect(),
    );
    c
}

#[test]
fn test_objectives_positive_wellknown_tool_is_ok() {
    // Objectives may freely reference well-known/{tool,app,lib,game}/
    // as positive evidence at any criticality — these are
    // legitimate-software identifiers, not malware-family attribution.
    let composites = vec![make_composite_suspicious(
        "objectives/credential-access/dump",
        &[
            "micro-behaviors/process/lsass",
            "well-known/tool/mimikatz/sekurlsa",
        ],
    )];
    let sources = HashMap::new();
    let v = find_objectives_wellknown_violations(&[], &composites, &sources);
    assert!(
        v.is_empty(),
        "objectives/ may reference well-known/{{tool,app,lib,game}}/ as positive evidence"
    );
}

#[test]
fn test_objectives_unless_wellknown_tool_is_ok() {
    let composites = vec![make_composite_with_unless(
        "objectives/credential-access/dump",
        &["micro-behaviors/process/lsass"],
        &["well-known/tool/sysinternals/procdump"],
    )];
    let sources = HashMap::new();
    let v = find_objectives_wellknown_violations(&[], &composites, &sources);
    assert!(
        v.is_empty(),
        "well-known/tool/ in `unless:` is benign-context suppression and is allowed"
    );
}

#[test]
fn test_objectives_unless_wellknown_malware_is_violation() {
    let composites = vec![make_composite_with_unless(
        "objectives/credential-access/dump",
        &["micro-behaviors/process/lsass"],
        &["well-known/malware/stealer/redline"],
    )];
    let sources = HashMap::new();
    let v = find_objectives_wellknown_violations(&[], &composites, &sources);
    assert_eq!(
        v.len(),
        1,
        "well-known/malware refs are forbidden even in unless/downgrade clauses"
    );
    assert_eq!(v[0].3, ObjectivesWellknownViolation::MalwareRef);
}

#[test]
fn test_objectives_positive_wellknown_malware_is_violation() {
    let composites = vec![make_composite(
        "objectives/credential-access/dump",
        &[
            "micro-behaviors/process/lsass",
            "well-known/malware/stealer/redline",
        ],
    )];
    let sources = HashMap::new();
    let v = find_objectives_wellknown_violations(&[], &composites, &sources);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].3, ObjectivesWellknownViolation::MalwareRef);
}

#[test]
fn test_non_objectives_skipped() {
    // The objectives/ check must not double-fire on micro-behaviors/ or metadata/ rules
    // (those are flagged by find_cap_wellknown_violations / find_metadata_cross_tier_refs).
    let composites = vec![
        make_composite(
            "micro-behaviors/foo",
            &["well-known/tool/mimikatz/sekurlsa"],
        ),
        make_composite("metadata/format/foo", &["well-known/lib/openssl/v3"]),
    ];
    let sources = HashMap::new();
    let v = find_objectives_wellknown_violations(&[], &composites, &sources);
    assert!(v.is_empty());
}

// ---- suppression-only building blocks ----

/// A baseline/component atomic leaf (raw matcher, no references).
fn leaf(id: &str, crit: Criticality) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "leaf".to_string(),
        conf: 1.0,
        crit,
        mbc: None,
        attack: None,
        r#if: Condition::Raw(crate::composite_rules::RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("needle".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

/// A composite with explicit crit, optional `any:`, and optional `unless:` references.
fn comp(id: &str, crit: Criticality, any: &[&str], unless: &[&str]) -> CompositeTrait {
    let to_conds = |refs: &[&str]| {
        refs.iter()
            .map(|r| Condition::Trait { id: r.to_string() })
            .collect::<Vec<_>>()
    };
    CompositeTrait {
        required_trait_indices: Vec::new(),
        id: id.to_string(),
        desc: "comp".to_string(),
        conf: 1.0,
        crit,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: (!any.is_empty()).then(|| to_conds(any)),
        unless: (!unless.is_empty()).then(|| to_conds(unless)),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

fn ids(v: &[(String, String)]) -> Vec<&str> {
    v.iter().map(|(id, _)| id.as_str()).collect()
}

#[test]
fn wellknown_baseline_is_invalid_even_when_used() {
    let traits = vec![
        leaf("well-known/tool/demo::baseline", Criticality::Baseline),
        leaf("well-known/tool/demo::component", Criticality::Component),
        leaf("well-known/tool/demo::notable", Criticality::Notable),
        leaf("metadata/file/size::baseline", Criticality::Baseline),
    ];
    let composites = vec![
        comp(
            "well-known/tool/demo::base-composite",
            Criticality::Baseline,
            &[],
            &[],
        ),
        comp(
            "well-known/tool/demo::identity",
            Criticality::Notable,
            &["well-known/tool/demo::baseline"],
            &[],
        ),
        comp(
            "well-known/tool/demo::exception",
            Criticality::Exception,
            &["well-known/tool/demo::notable"],
            &[],
        ),
        comp("objectives/demo::baseline", Criticality::Baseline, &[], &[]),
    ];
    let violations = find_wellknown_baseline_rules(&traits, &composites, &HashMap::new());
    assert_eq!(
        ids(&violations),
        vec![
            "well-known/tool/demo::base-composite",
            "well-known/tool/demo::baseline"
        ]
    );
}

#[test]
fn exception_composites_are_not_suppression_only_violations() {
    let traits = vec![leaf("well-known/tool/demo::evidence", Criticality::Notable)];
    let composites = vec![
        comp(
            "well-known/tool/demo::context",
            Criticality::Exception,
            &["well-known/tool/demo::evidence"],
            &[],
        ),
        comp(
            "objectives/evasion/demo::detection",
            Criticality::Suspicious,
            &["micro-behaviors/demo::evidence"],
            &["well-known/tool/demo::context"],
        ),
    ];
    assert!(
        find_suppression_only_building_blocks(&traits, &composites, &HashMap::new()).is_empty()
    );
}

#[test]
fn wellknown_basename_facts_have_a_notable_ceiling_and_need_no_size() {
    let mut name = leaf("well-known/tool/demo::filename", Criticality::Notable);
    name.r#for = vec![FileType::Elf];
    name.r#if = Condition::Path(PathQuery {
        exact: Some("demo".into()),
        basename: true,
        ..Default::default()
    });
    assert!(find_wellknown_missing_size_filter(&[name.clone()], &HashMap::new()).is_empty());
    assert!(find_wellknown_high_criticality_basenames(&[name.clone()], &HashMap::new()).is_empty());
    name.crit = Criticality::Suspicious;
    assert_eq!(
        ids(&find_wellknown_high_criticality_basenames(
            &[name.clone()],
            &HashMap::new()
        )),
        vec!["well-known/tool/demo::filename"]
    );
    assert_eq!(
        ids(&find_wellknown_missing_size_filter(
            &[name],
            &HashMap::new()
        )),
        vec!["well-known/tool/demo::filename"]
    );

    let mut content = leaf("well-known/tool/demo::content", Criticality::Notable);
    content.r#for = vec![FileType::Elf];
    assert_eq!(
        ids(&find_wellknown_missing_size_filter(
            &[content],
            &HashMap::new()
        )),
        vec!["well-known/tool/demo::content"]
    );

    let mut full_path = leaf("well-known/tool/demo::path", Criticality::Notable);
    full_path.r#for = vec![FileType::Elf];
    full_path.r#if = Condition::Path(PathQuery {
        exact: Some("/usr/bin/demo".into()),
        ..Default::default()
    });
    assert_eq!(
        ids(&find_wellknown_missing_size_filter(
            &[full_path],
            &HashMap::new()
        )),
        vec!["well-known/tool/demo::path"]
    );
}

#[test]
fn repeated_trezor_reference_size_exception_is_matcher_specific() {
    let mut fact = leaf(
        "well-known/app/finance/trezor::repeated-trezor-token",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: trezor\n").unwrap();
    fact.count_min = Some(4);
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    let mut weaker = fact.clone();
    weaker.count_min = Some(3);
    assert_eq!(
        find_wellknown_missing_size_filter(&[weaker], &HashMap::new()).len(),
        1
    );
    let mut different = fact.clone();
    different.r#if = crate::yaml::from_str("type: text\nsubstr: other\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[different], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn reviewed_netscape_name_reference_needs_no_size_bound() {
    let mut fact = leaf(
        "well-known/app/browser/netscape::netscape-name-text-reference",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str(
        "type: text\nregex: '(?i)(Netscape Navigator|Netscape Communicator)'\nsection: .text\n",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nregex: other\nsection: .text\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn reviewed_msvc_runtime_path_needs_no_size_bound() {
    let mut path = leaf(
        "well-known/lib/runtime/compiled/msvc-runtime::bin64-msvcr120-path",
        Criticality::Notable,
    );
    path.r#for = vec![FileType::Pe];
    path.r#if = Condition::Path(PathQuery {
        substr: Some("bin64/msvcr120.dll".into()),
        ..Default::default()
    });
    assert!(find_wellknown_missing_size_filter(&[path.clone()], &HashMap::new()).is_empty());
    let mut different_match = path.clone();
    different_match.r#if = Condition::Path(PathQuery {
        substr: Some("another.dll".into()),
        ..Default::default()
    });
    assert_eq!(
        find_wellknown_missing_size_filter(&[different_match], &HashMap::new()).len(),
        1
    );
    let mut higher_criticality = path.clone();
    higher_criticality.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[higher_criticality], &HashMap::new()).len(),
        1
    );
    path.id = "well-known/lib/runtime/compiled/msvc-runtime::other-path".into();
    assert_eq!(
        find_wellknown_missing_size_filter(&[path], &HashMap::new()).len(),
        1
    );
}

#[test]
fn reviewed_named_references_require_the_specific_matcher_and_criticality() {
    let mut fact = leaf(
        "well-known/lib/runtime/scripted/gentee::gentee-runtime-call",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str("type: text\nexact: gentee_call\n").unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nexact: unrelated\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn reviewed_sshtty_references_preserve_whole_file_scope() {
    for (id, marker) in [
        ("sshtty-server-crate-marker", "sshtty::server"),
        (
            "sshtty-terminal-banner",
            "Browser terminal with groups and tabs that keeps your shells running",
        ),
    ] {
        let mut fact = leaf(
            &format!("well-known/app/system/sshtty::{id}"),
            Criticality::Notable,
        );
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!("type: text\nsubstr: '{marker}'\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn python_launcher_banner_exception_requires_exact_notable_marker() {
    let mut fact = leaf(
        "well-known/lib/runtime/scripted/python-runtime::python-launcher-banner-marker",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if =
        crate::yaml::from_str("type: text\nexact: 'Python Launcher for Windows Version %ls'\n")
            .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nexact: 'unrelated'\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn sms_provider_exceptions_require_exact_notable_references() {
    for (id, endpoint) in [
        (
            "well-known/app/communication/weimi::weimi-cc-api",
            "api.weimi.cc/",
        ),
        (
            "well-known/app/communication/weimi::weimi-cc-admin",
            "www.weimi.cc/sms.html",
        ),
        (
            "well-known/app/communication/juhe::juhe-cn-sms-send",
            "v.juhe.cn/sms/",
        ),
    ] {
        let mut fact = leaf(id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!("type: text\nsubstr: {endpoint}\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn mixcloud_warning_exception_requires_exact_notable_reference() {
    let mut fact = leaf(
        "well-known/app/media/mixcloud::mixcloud-download-warning",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str(
        "type: text\nsubstr: IFYOUWANTTHEARTISTSTOGETPAIDDONOTDOWNLOADFROMMIXCLOUD\n",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn minicap_size_exception_requires_exact_notable_path() {
    let mut fact = leaf(
        "well-known/tool/development/automation/minicap::android-staged-minicap-path",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str("type: text\nregex: '/data/local/tmp/minicap\\b'\n").unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nregex: unrelated\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn poolpartybof_size_exception_requires_exact_notable_reference() {
    let mut fact = leaf(
        "well-known/tool/offensive/poolpartybof::poolparty-bof-name",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: PoolPartyBof\n").unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn nvidia_nvml_size_exception_requires_reviewed_section_scoped_reference() {
    for (id, marker) in [
        ("nvml-wrapper-rust-crate", "nvml-wrapper-sys"),
        (
            "nvidia-gpu-classifier-token",
            "NvidiaQuadroTeslaNVSGRIDGeForceTitanV",
        ),
    ] {
        let mut fact = leaf(
            &format!("well-known/lib/runtime/native-platform/nvidia-nvml::{id}"),
            Criticality::Notable,
        );
        fact.r#for = vec![FileType::Pe];
        fact.r#if =
            crate::yaml::from_str(&format!("type: text\nsubstr: {marker}\nsection: rdata\n"))
                .unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        fact.crit = Criticality::Notable;
        fact.r#if =
            crate::yaml::from_str("type: text\nsubstr: unrelated\nsection: rdata\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn reviewed_dotnet_tool_references_do_not_need_size_bounds() {
    for (id, yaml) in [
        (
            "servicemodelreg-exe-name",
            "type: text\nregex: '(?i)\\bServiceModelReg\\.exe\\b'\n",
        ),
        (
            "addinprocess32-exe-name",
            "type: text\nregex: '(?i)\\bAddInProcess32\\.exe\\b'\n",
        ),
        (
            "regasm-exe-name",
            "type: text\nregex: '(?i)\\bRegAsm\\.exe\\b'\n",
        ),
        (
            "installutil-exe-name",
            "type: text\nregex: '(?i)\\bInstallUtil\\.exe\\b'\n",
        ),
        (
            "mscorsvw-exe-name",
            "type: text\nregex: '(?i)\\bmscorsvw\\.exe\\b'\n",
        ),
        ("msbuild-exe-name", "type: text\nword: MSBuild.exe\n"),
        (
            "aspnet-tool-exe-name",
            "type: text\nregex: 'aspnet_(compiler|regiis|state|wp)\\.exe'\n",
        ),
    ] {
        let mut fact = leaf(
            &format!("well-known/lib/runtime/managed/dotnet-runtime::{id}"),
            Criticality::Notable,
        );
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(yaml).unwrap();
        assert!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1,
            "{id}"
        );
    }
}

#[test]
fn gentee_runtime_reference_exceptions_are_matcher_specific() {
    let cases = [
        ("gentee-runtime-init", "exact", "gentee_init"),
        ("gentee-runtime-deinit", "exact", "gentee_deinit"),
        ("gentee-runtime-load", "exact", "gentee_load"),
        ("gentee-runtime-set", "exact", "gentee_set"),
        ("gentee-runtime-call", "exact", "gentee_call"),
        ("gentee-runtime-dll-name", "substr", "genteert.dll"),
    ];
    for (name, kind, pattern) in cases {
        let id = format!("well-known/lib/runtime/scripted/gentee::{name}");
        let mut fact = leaf(&id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!("type: text\n{kind}: {pattern}\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn windows_rpc_service_size_exceptions_are_matcher_specific() {
    let cases = [
        (
            "well-known/app/security/defender::defender-rpc-uuid",
            "regex",
            r"(?i)c503f532-443a-4c69-8300-ccd1fbdb3839",
        ),
        (
            "well-known/app/security/defender::defender-mpservice-alpc",
            "substr",
            "IMpService77BDAF73-B396-481F-9042-AD358843EC24",
        ),
        (
            "well-known/app/system/microsoft/platform::appinfo-elevation-interface-uuid",
            "regex",
            r"(?i)\{?201ef99a[-, ]+7fa0[-, ]+444c[-, ]+9399[-, ]+19ba84f12a1a\}?",
        ),
    ];
    for (id, kind, pattern) in cases {
        let mut fact = leaf(id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!("type: text\n{kind}: '{pattern}'\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn sumatrapdf_claim_size_exception_is_matcher_specific() {
    let mut fact = leaf(
        "well-known/app/productivity/sumatrapdf::sumatrapdf-encryption-sentinel",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str(
        "type: text\nregex: 'This document is encrypted with sumatrapdf reader!{4,}'\n",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn jwe_library_reference_exceptions_are_matcher_specific() {
    let cases = [
        (
            "well-known/lib/runtime/managed/dotnet-runtime::jwt-jwe-context--rx-2",
            "System.Security.Cryptography.Pkcs",
        ),
        (
            "well-known/lib/crypto/jose-jwt::jwt-jwe-context--rx-6",
            "jose-jwt",
        ),
    ];
    for (id, pattern) in cases {
        let mut fact = leaf(id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!("type: text\nsubstr: '{pattern}'\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn apple_cache_service_size_exception_is_matcher_specific() {
    let mut fact = leaf(
        "well-known/app/system/apple/launch-services::apple-like-cache-service-name",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Macho];
    fact.r#if = crate::yaml::from_str(
        r"type: text
regex: '(?i)(com\.apple\.(verified|homeenergyd)|/com\.apple\.softwareupdate/SoftwareUpdate)\b'
",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn windows_product_name_exceptions_are_matcher_specific() {
    let cases = [
        (
            "well-known/app/system/microsoft/error-reporting::windows-error-reporter-manifest-reference",
            "exact",
            "name=\"Microsoft.Windows.ErrorReporter\"",
            Criticality::Notable,
        ),
        (
            "well-known/game/mahjong-titans::mahjong-titans-name-reference",
            "substr",
            "Mahjong Titans",
            Criticality::Notable,
        ),
        (
            "well-known/app/productivity/microsoft-office::officecompleted-text",
            "exact",
            "OfficeCompleted",
            Criticality::Component,
        ),
        (
            "well-known/app/productivity/microsoft-office::office-help-viewer-name",
            "exact",
            "Microsoft Office Help Viewer",
            Criticality::Notable,
        ),
        (
            "well-known/app/productivity/microsoft-office::office-help-path",
            "exact",
            "/MsOfficeHelp16/",
            Criticality::Notable,
        ),
        (
            "well-known/app/productivity/microsoft-office::msoxmled-pdb",
            "substr",
            "msoxmled.pdb",
            Criticality::Notable,
        ),
        (
            "well-known/app/productivity/microsoft-office::vsto-installer-pdb-reference",
            "exact",
            "VSTOInstaller.pdb",
            Criticality::Notable,
        ),
        (
            "well-known/app/productivity/microsoft-office::ensure-vsto-component-text",
            "exact",
            "EnsureVSTOComponent",
            Criticality::Notable,
        ),
        (
            "well-known/app/productivity/microsoft-office::office-help-user-agent-text",
            "exact",
            "User-Agent: %s%sX-OfApp: %s%sX-OfVer: %s%sX-Office-Version: %d.%d.%04d.0%sX-OfHelpLcid: %s%sX-OfUILcid: %s%sX-OfSysLcid: %s%s",
            Criticality::Notable,
        ),
        (
            "well-known/app/system/microsoft/telemetry::diagtrackrunner-pdb",
            "exact",
            "diagtrackrunner.pdb",
            Criticality::Notable,
        ),
        (
            "well-known/app/system/microsoft/telemetry::diagtrack-dll-name",
            "exact",
            "diagtrack.dll",
            Criticality::Notable,
        ),
    ];
    for (id, kind, pattern, crit) in cases {
        let mut fact = leaf(id, crit);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!(
            "type: text\n{kind}: {}\n",
            serde_json::to_string(pattern).unwrap()
        ))
        .unwrap();
        assert!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        assert!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        fact.crit = crit;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1,
            "{id}"
        );
    }
}

#[test]
fn legacy_product_name_size_exceptions_are_matcher_specific() {
    let cases = [
        (
            "well-known/app/productivity/lotus-approach::lotus-approach-name-reference",
            "(?i)Lotus Approach",
        ),
        (
            "well-known/lib/development/borland-delphi::borland-delphi-name-reference",
            "(?i)Borland Delphi",
        ),
    ];
    for (id, pattern) in cases {
        let mut fact = leaf(id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!(
            "type: text\nregex: {}\n",
            serde_json::to_string(pattern).unwrap()
        ))
        .unwrap();
        assert!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1,
            "{id}"
        );
    }
}

#[test]
fn product_registry_reference_exceptions_are_matcher_specific() {
    let cases = [
        (
            "well-known/lib/runtime/managed/java-runtime::java-runtime-home-key-reference",
            "exact",
            r"SOFTWARE\JavaSoft\Java Runtime Environment",
        ),
        (
            "well-known/game/roblox::roblox-studio-registry-key",
            "regex",
            r"(?i)SOFTWARE[\\/]Roblox[\\/]RobloxStudioBrowser[\\/]roblox\.com",
        ),
        (
            "well-known/game/steam-registry::steam-path-string",
            "substr",
            r"Software\Valve\Steam",
        ),
        (
            "well-known/app/productivity/onenote::onenote-options-other-policy-path",
            "exact",
            r"Software\Policies\Microsoft\Office\16.0\OneNote\Options\Other",
        ),
        (
            "well-known/app/system/pcanywhere::pcanywhere-data-port-reference",
            "substr",
            r"Symantec\pcAnywhere\CurrentVersion\System\TCPIPDataPort",
        ),
        (
            "well-known/app/productivity/lotus-approach::registry-path-lotus",
            "regex",
            r"(?i)Software\\Lotus\\Approach",
        ),
        (
            "well-known/app/communication/aol-desktop::registry-path-aol",
            "regex",
            r"(?i)Software\\AOL\\Desktop",
        ),
        (
            "well-known/app/enterprise/symantec-act::registry-path-symantec-act",
            "regex",
            r"(?i)Software\\Symantec\\ACT!",
        ),
        (
            "well-known/app/communication/compuserve::registry-path-compuserve",
            "regex",
            r"(?i)Software\\Compuserve",
        ),
    ];
    for (id, kind, pattern) in cases {
        let mut fact = leaf(id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!(
            "type: text\n{kind}: {}\n",
            serde_json::to_string(pattern).unwrap()
        ))
        .unwrap();
        assert!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        assert!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1,
            "{id}"
        );
    }
}

#[test]
fn named_manifest_description_does_not_need_file_size() {
    let mut fact = leaf(
        "well-known/app/utility/getrighttogo::getrighttogo-manifest",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str(
        "type: value\npath: pe.manifest.description\nexact: GetRightToGo.com Downloader\n",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn nping_command_reference_size_exceptions_are_matcher_specific() {
    let cases = [
        (
            "well-known/tool/offensive/reconnaissance/nping::nping",
            "word",
            "nping",
        ),
        (
            "well-known/tool/offensive/reconnaissance/nping::source-port",
            "regex",
            r"(?i)\bnping\b[^\r\n]{0,300}--source-port",
        ),
        (
            "well-known/tool/offensive/reconnaissance/nping::payload-data",
            "regex",
            r"(?i)\bnping\b[^\r\n]{0,300}--data=",
        ),
    ];
    for (id, kind, pattern) in cases {
        let mut fact = leaf(id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        fact.r#if = crate::yaml::from_str(&format!(
            "type: text\n{kind}: {}\n",
            serde_json::to_string(pattern).unwrap()
        ))
        .unwrap();
        assert!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nword: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1,
            "{id}"
        );
    }
}

#[test]
fn remote_tool_reference_size_exceptions_are_matcher_specific() {
    let cases = [
        (
            "well-known/tool/offensive/impacket::impacket-psexec-script-reference",
            r"(?i)\bpsexec\.py\b",
        ),
        (
            "well-known/tool/offensive/impacket::impacket-wmiexec-script-reference",
            r"(?i)(impacket[\\/]examples[\\/]wmiexec\.py|wmiexec\.py)\b",
        ),
        (
            "well-known/tool/offensive/impacket::impacket-wmiexec-target",
            r"(?i)\bwmiexec\.py\b[^\r\n]{0,180}@(\[[^\]\r\n]{1,40}\]|[A-Za-z0-9_.-]+)",
        ),
        (
            "well-known/tool/sysadmin/sysinternals::psexec-remote-invocation",
            r#"(?i)\bpsexec(64)?(\.exe)?\b[^\r\n]{0,160}\s+["']?\\\\[\w.%${}<>-]{1,80}(\s|["']|$)"#,
        ),
    ];
    for (id, pattern) in cases {
        let mut fact = leaf(id, Criticality::Notable);
        fact.r#for = vec![FileType::Pe];
        let yaml = format!(
            "type: text\nregex: {}\n",
            serde_json::to_string(pattern).unwrap()
        );
        fact.r#if = crate::yaml::from_str(&yaml).unwrap();
        assert!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        fact.crit = Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1,
            "{id}"
        );
        fact.crit = Criticality::Notable;
        fact.r#if = crate::yaml::from_str("type: text\nregex: other\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1,
            "{id}"
        );
    }
}

#[test]
fn tauri_plugin_reference_has_a_narrow_size_exception() {
    let mut fact = leaf(
        "well-known/lib/development/tauri::tauri-shell-open-plugin",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: 'plugin:shell|open'\nsection: .rdata\n")
        .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if =
        crate::yaml::from_str("type: text\nsubstr: 'plugin:shell|open'\nsection: .text\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn plex_plugin_route_size_exception_is_matcher_specific() {
    let mut fact = leaf(
        "well-known/app/media/plex::plex-plugin-network-function-route",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str(
        r#"type: text
regex: 'com\.plexapp\.agents\.[\w.]+(/|%2[fF])function(/|%2[fF])GetResultFromNetwork'
"#,
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nregex: 'com\\.plexapp\\.other'\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn mshta_name_size_exception_is_matcher_specific() {
    let mut fact = leaf(
        "well-known/app/system/microsoft/mshta::mshta-exe-literal",
        Criticality::Notable,
    );
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str("type: text\nsection: rdata\nexact: mshta.exe\n").unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nsection: rdata\nexact: other.exe\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn call_argument_predicates_are_not_bare_name_duplicates() {
    use crate::capabilities::validation::duplicates::find_regex_literal_overlap_issues;
    let mut base = leaf("micro-behaviors/fs/file/open::fopen", Criticality::Notable);
    base.defined_in = PathBuf::from("open.yaml");
    base.r#for = vec![FileType::Php];
    base.r#if = crate::yaml::from_str("type: symbol\nkind: call\nexact: fopen\n").unwrap();
    let mut mode = leaf(
        "micro-behaviors/fs/file/io-mode::append",
        Criticality::Notable,
    );
    mode.defined_in = PathBuf::from("mode.yaml");
    mode.r#for = vec![FileType::Php];
    mode.r#if = crate::yaml::from_str(
        r#"type: symbol
kind: call
regex: '^\\?fopen$'
arg: {index: 1, exact: a}
"#,
    )
    .unwrap();
    assert!(find_regex_literal_overlap_issues(&[base.clone(), mode.clone()]).is_empty());
    mode.r#if = crate::yaml::from_str(
        r#"type: symbol
kind: call
regex: '^\\?fopen$'
"#,
    )
    .unwrap();
    assert!(!find_regex_literal_overlap_issues(&[base, mode]).is_empty());
}

#[test]
fn low_tier_named_binary_facts_do_not_need_arbitrary_size() {
    let mut fact = leaf("well-known/app/demo::claim", Criticality::Notable);
    fact.r#for = vec![FileType::Pe];
    for yaml in [
        "type: value\npath: pe.version.product_name\nexact: Example\n",
        "type: value\npath: pe.manifest.assembly_identity.name\nexact: Example.Tool\n",
        "type: value\npath: pe.signatures[0].subject\nexact: CN=Example\n",
        "type: text\nsection: .rsrc\nexact: Example\n",
    ] {
        fact.r#if = crate::yaml::from_str(yaml).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    }
    fact.r#if = crate::yaml::from_str(
        "type: value\npath: pe.manifest.assembly_identity.name\nexists: true\n",
    )
    .unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.r#if =
        crate::yaml::from_str("type: value\npath: pe.version.product_name\nexact: Example\n")
            .unwrap();
    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.id = "well-known/malware/demo::claim".to_string();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.id = "well-known/app/demo::claim".to_string();
    fact.r#if = crate::yaml::from_str("type: value\npath: pe.version.product_name\nexists: true\n")
        .unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn reviewed_schneider_reference_size_allowance_is_specific() {
    let id = "well-known/app/infrastructure/industrial-control/schneider-electric::industrial-product-reference";
    let mut fact = leaf(id, Criticality::Notable);
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str(
        "type: text\nregex: '(?i)Schneider\\s*Electric.{0,30}(Desal|Unity|SoMachine|EcoStruxure)'\n",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());

    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.id = "well-known/app/infrastructure/other::industrial-product-reference".into();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.id = id.into();
    fact.r#if = crate::yaml::from_str("type: text\nregex: Schneider\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn reviewed_preference_name_allowance_is_specific() {
    let id = "well-known/app/media/plex::plex-transcoder-h264-options-binary";
    let mut fact = leaf(id, Criticality::Notable);
    fact.r#for = vec![FileType::Pe];
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: TranscoderH264Options\n").unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());

    fact.crit = Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.crit = Criticality::Notable;
    fact.id = "well-known/app/media/other::preference".to_string();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    fact.id = id.to_string();
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: Transcoder\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn flags_baseline_leaf_referenced_only_in_unless() {
    let traits = vec![leaf(
        "objectives/evasion/x::benign-ctx",
        Criticality::Baseline,
    )];
    // A notable composite that only *suppresses* on the leaf.
    let composites = vec![comp(
        "objectives/evasion/x::detect",
        Criticality::Notable,
        &["micro-behaviors/foo::bar"],
        &["objectives/evasion/x::benign-ctx"],
    )];
    let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
    assert_eq!(ids(&v), vec!["objectives/evasion/x::benign-ctx"]);
}

#[test]
fn exempt_when_positive_evidence_in_notable_composite() {
    let traits = vec![leaf("objectives/evasion/x::probe", Criticality::Baseline)];
    let composites = vec![comp(
        "objectives/evasion/x::detect",
        Criticality::Notable,
        &["objectives/evasion/x::probe"],
        &[],
    )];
    let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
    assert!(
        v.is_empty(),
        "positive ref by a notable composite satisfies"
    );
}

#[test]
fn exempt_transitively_through_baseline_aggregator() {
    // component fragment -> baseline aggregator -> notable composite.
    let traits = vec![leaf("objectives/evasion/x::frag", Criticality::Component)];
    let composites = vec![
        comp(
            "objectives/evasion/x::agg",
            Criticality::Baseline,
            &["objectives/evasion/x::frag"],
            &[],
        ),
        comp(
            "objectives/evasion/x::detect",
            Criticality::Notable,
            &["objectives/evasion/x::agg"],
            &[],
        ),
    ];
    let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
    assert!(
        v.is_empty(),
        "a fragment feeding a notable detection transitively is fine, got {:?}",
        ids(&v)
    );
}

#[test]
fn flags_chain_that_never_reaches_notable() {
    // fragment -> baseline aggregator, but nothing notable consumes the aggregator.
    let traits = vec![leaf("objectives/evasion/x::frag", Criticality::Component)];
    let composites = vec![comp(
        "objectives/evasion/x::agg",
        Criticality::Baseline,
        &["objectives/evasion/x::frag"],
        &[],
    )];
    let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
    // Both the fragment and the baseline aggregator are unreached building blocks.
    assert_eq!(
        ids(&v),
        vec!["objectives/evasion/x::agg", "objectives/evasion/x::frag"]
    );
}

#[test]
fn directory_reference_from_notable_satisfies_members() {
    let traits = vec![leaf(
        "well-known/malware/foo::marker",
        Criticality::Baseline,
    )];
    // Notable composite references the directory, not the specific id.
    let composites = vec![comp(
        "well-known/malware/foo::detect",
        Criticality::Notable,
        &["well-known/malware/foo"],
        &[],
    )];
    let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
    assert!(v.is_empty(), "a directory ref covers members beneath it");
}

#[test]
fn ignores_other_tiers() {
    // micro-behaviors/ and metadata/ are out of scope even when only suppressed.
    let traits = vec![leaf("micro-behaviors/foo::ctx", Criticality::Baseline)];
    let composites = vec![comp(
        "objectives/evasion/x::detect",
        Criticality::Notable,
        &["other::thing"],
        &["micro-behaviors/foo::ctx"],
    )];
    let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
    assert!(
        v.is_empty(),
        "only objectives/ and well-known/ are candidates"
    );
}

#[test]
fn notable_rule_itself_is_not_a_candidate() {
    // A notable leaf in objectives/ surfaces on its own — not a building block.
    let traits = vec![leaf(
        "objectives/evasion/x::standalone",
        Criticality::Notable,
    )];
    let v = find_suppression_only_building_blocks(&traits, &[], &HashMap::new());
    assert!(v.is_empty());
}

#[test]
fn test_oversized_dir_uses_uniform_combined_limit() {
    let reviewed_path = "micro-behaviors/communications/http/url/path";
    let reviewed_rules: Vec<_> = (0..MAX_TRAITS_PER_DIRECTORY + 2)
        .map(|i| make_trait(&format!("{reviewed_path}::r{i}"), "other::t"))
        .collect();
    assert_eq!(
        find_oversized_trait_directories(&reviewed_rules, &[]),
        vec![(reviewed_path.to_string(), MAX_TRAITS_PER_DIRECTORY + 2)]
    );
    let unreviewed_sibling: Vec<_> = (0..MAX_TRAITS_PER_DIRECTORY + 2)
        .map(|i| {
            make_trait(
                &format!("micro-behaviors/communications/http/url/host::r{i}"),
                "other::t",
            )
        })
        .collect();
    assert_eq!(
        find_oversized_trait_directories(&unreviewed_sibling, &[]),
        vec![(
            "micro-behaviors/communications/http/url/host".to_string(),
            MAX_TRAITS_PER_DIRECTORY + 2
        )]
    );
    for dir in [
        "objectives/evasion/x",
        "objectives/command-and-control/reverse-shell/dup",
    ] {
        // Cover atom-only, composite-only, and mixed directories, including
        // more than 75 atoms: there is no separate atomic cap.
        for atoms in [0, 42, 76, MAX_TRAITS_PER_DIRECTORY] {
            let traits: Vec<_> = (0..atoms)
                .map(|i| make_trait(&format!("{dir}::a{i}"), "other::t"))
                .collect();
            let mut rules: Vec<_> = (0..MAX_TRAITS_PER_DIRECTORY - atoms)
                .map(|i| make_composite(&format!("{dir}::c{i}"), &["other::t"]))
                .collect();
            assert!(find_oversized_trait_directories(&traits, &rules).is_empty());
            // A different directory must not consume this directory's budget.
            rules.push(make_composite("objectives/evasion/y::other", &["other::t"]));
            assert!(find_oversized_trait_directories(&traits, &rules).is_empty());
            rules.push(make_composite(&format!("{dir}::extra"), &["other::t"]));
            assert_eq!(
                find_oversized_trait_directories(&traits, &rules),
                vec![(dir.to_string(), MAX_TRAITS_PER_DIRECTORY + 1)]
            );
        }
        let traits: Vec<_> = (0..=MAX_TRAITS_PER_DIRECTORY)
            .map(|i| make_trait(&format!("{dir}::a{i}"), "other::t"))
            .collect();
        assert_eq!(
            find_oversized_trait_directories(&traits, &[]),
            vec![(dir.to_string(), MAX_TRAITS_PER_DIRECTORY + 1)]
        );
    }
}

#[test]
fn test_depth_review_counts_below_tier_and_allows_five() {
    for tier in ["micro-behaviors", "objectives", "metadata", "well-known"] {
        let five = format!("{tier}/a/b/c/d/e");
        let six = format!("{five}/f");
        let seven = format!("{six}/g");
        assert_eq!(
            find_deep_taxonomy_directories(&[
                seven.clone(),
                five,
                tier.to_string(),
                six.clone(),
                six.clone(),
            ]),
            vec![(six, 6), (seven, 7)]
        );
    }
    assert!(find_deep_taxonomy_directories(&["unrelated/a/b/c/d/e/f".to_string()]).is_empty());
}

#[test]
fn sparse_checks_apply_to_formerly_reviewed_partitions() {
    let codec = HashMap::from([
        ("micro-behaviors/data/codec/gzip".to_string(), 7),
        ("micro-behaviors/data/codec/lzma".to_string(), 1),
        ("micro-behaviors/data/codec/zlib".to_string(), 1),
    ]);
    assert_eq!(
        find_sparse_sibling_cohorts(&codec),
        vec![("micro-behaviors/data/codec".to_string(), 9, 3)]
    );
    let codec_with_new_sibling = HashMap::from([
        ("micro-behaviors/data/codec/gzip".to_string(), 7),
        ("micro-behaviors/data/codec/lzma".to_string(), 1),
        ("micro-behaviors/data/codec/zlib".to_string(), 1),
        ("micro-behaviors/data/codec/bzip2".to_string(), 1),
    ]);
    assert_eq!(
        find_sparse_sibling_cohorts(&codec_with_new_sibling),
        vec![("micro-behaviors/data/codec".to_string(), 10, 4)]
    );

    let mut rules = HashMap::from([
        ("micro-behaviors/fs/swap/on".to_string(), 1),
        ("micro-behaviors/fs/swap/off".to_string(), 2),
    ]);
    assert_eq!(
        find_sparse_sibling_cohorts(&rules),
        vec![("micro-behaviors/fs/swap".to_string(), 3, 2)]
    );
    rules.insert("micro-behaviors/fs/swap/helper".to_string(), 1);
    assert_eq!(
        find_sparse_sibling_cohorts(&rules),
        vec![("micro-behaviors/fs/swap".to_string(), 4, 3)]
    );
    let unreviewed = HashMap::from([
        ("micro-behaviors/fs/swap-copy/on".to_string(), 1),
        ("micro-behaviors/fs/swap-copy/off".to_string(), 2),
    ]);
    assert_eq!(
        find_sparse_sibling_cohorts(&unreviewed),
        vec![("micro-behaviors/fs/swap-copy".to_string(), 3, 2)]
    );
    let renamed = HashMap::from([
        ("micro-behaviors/fs/swap/on".to_string(), 1),
        ("micro-behaviors/fs/swap/stop".to_string(), 2),
    ]);
    assert_eq!(
        find_sparse_sibling_cohorts(&renamed),
        vec![("micro-behaviors/fs/swap".to_string(), 3, 2)]
    );
}

#[test]
fn test_sparse_sibling_cohorts_use_35_rule_limit_and_skip_single_child() {
    let rules = HashMap::from([
        ("objectives/evasion/technique-small/a".to_string(), 17),
        ("objectives/evasion/technique-small/b".to_string(), 17),
        ("objectives/evasion/technique-limit/a".to_string(), 17),
        ("objectives/evasion/technique-limit/b".to_string(), 18),
        ("objectives/evasion/single-child/only".to_string(), 1),
        ("well-known/tool/a".to_string(), 1),
        ("well-known/tool/b".to_string(), 1),
    ]);

    assert_eq!(
        find_sparse_sibling_cohorts(&rules),
        vec![("objectives/evasion/technique-small".to_string(), 34, 2)]
    );
}

#[test]
fn sparse_siblings_require_ten_children_and_average_at_most_eight() {
    let rules: HashMap<String, usize> = (0..10)
        .map(|i| (format!("micro-behaviors/data/codec/c{i}"), 8))
        .collect();
    assert_eq!(
        find_fragmented_sibling_cohorts(&rules),
        vec![("micro-behaviors/data/codec".to_string(), 10, 80, 8.0)]
    );

    let nine_children: HashMap<String, usize> = (0..9)
        .map(|i| (format!("micro-behaviors/data/codec/c{i}"), 1))
        .collect();
    assert!(find_fragmented_sibling_cohorts(&nine_children).is_empty());

    let above_boundary: HashMap<String, usize> = (0..10)
        .map(|i| (format!("micro-behaviors/data/codec/c{i}"), 9))
        .collect();
    assert!(find_fragmented_sibling_cohorts(&above_boundary).is_empty());

    // The tier is respected: well-known catalogues are not scanned.
    let wk: HashMap<String, usize> = (0..6)
        .map(|i| (format!("well-known/tool/dev/t{i}"), 3))
        .collect();
    assert!(find_fragmented_sibling_cohorts(&wk).is_empty());
}

/// Composite rules count toward the directory cap alongside atomic traits:
/// a directory of few atoms and many roll-ups is just as flat.
#[test]
fn test_oversized_dir_counts_atomic_and_composite() {
    let dir = "objectives/evasion/x";
    let atoms = MAX_TRAITS_PER_DIRECTORY / 2;
    let traits: Vec<_> = (0..atoms)
        .map(|i| make_trait(&format!("{dir}::a{i}"), "other::t"))
        .collect();
    let mut rules: Vec<_> = (0..MAX_TRAITS_PER_DIRECTORY - atoms)
        .map(|i| make_composite(&format!("{dir}::c{i}"), &["other::t"]))
        .collect();
    assert!(
        find_oversized_trait_directories(&traits, &rules).is_empty(),
        "exactly at the cap must pass"
    );

    rules.push(make_composite(&format!("{dir}::extra"), &["other::t"]));
    assert_eq!(
        find_oversized_trait_directories(&traits, &rules),
        vec![(dir.to_string(), MAX_TRAITS_PER_DIRECTORY + 1)]
    );
    assert!(
        find_oversized_trait_directories(&traits, &[]).is_empty(),
        "atoms alone are under the cap"
    );
}

#[test]
fn all_former_budget_paths_reject_rules_above_the_cap() {
    for directory in [
        "metadata/filename",
        "metadata/file/archive",
        "metadata/package/dependencies/manifest/identity",
        "micro-behaviors/data/decode/base64",
        "micro-behaviors/fs/file/copy",
        "objectives/exfiltration/stealer/credential",
        "micro-behaviors/communications/http/header/custom",
        "micro-behaviors/communications/http/post",
        "micro-behaviors/communications/http/request/body",
        "micro-behaviors/communications/http/upload",
        "micro-behaviors/communications/http/url/path",
        "micro-behaviors/fs/path/credential",
        "micro-behaviors/fs/write/file/full",
        "micro-behaviors/os/user/account",
    ] {
        let traits: Vec<_> = (0..=MAX_TRAITS_PER_DIRECTORY)
            .map(|i| make_trait(&format!("{directory}::rule-{i}"), "other::t"))
            .collect();
        assert_eq!(
            find_oversized_trait_directories(&traits, &[]),
            vec![(directory.to_string(), MAX_TRAITS_PER_DIRECTORY + 1)]
        );
    }
}
