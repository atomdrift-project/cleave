#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use crate::types::traits_findings::{Evidence, FindingKind};

fn test_target() -> TargetInfo {
    TargetInfo {
        path: "/test/sample.bin".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: "abc123".to_string(),
        architectures: Some(vec!["x86_64".to_string()]),
    }
}

fn test_finding(id: &str, crit: Criticality) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        id: id.to_string().into(),
        kind: FindingKind::Capability,
        desc: format!("Test finding {}", id).into(),
        conf: 0.9,
        crit,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
        downgraded: false,
    }
}

/// Both report→file conversions must carry `suppressions`: the consuming
/// one serves every archive member, subfile and payload, and dropping the
/// field there silently erased the record of what the engine withheld.
#[test]
fn file_analysis_conversions_keep_suppressions() {
    let mut report = AnalysisReport::new(test_target());
    report.suppressions.push(Suppression {
        id: "objectives/execution/shell".into(),
        crit: Criticality::Suspicious,
        kind: crate::types::SuppressionKind::Unless,
        by: vec![],
    });

    let borrowed = report.to_file_analysis(0, &crate::Engine::empty());
    let (consumed, _, _) = report.into_file_analysis(0, &crate::Engine::empty());
    assert_eq!(borrowed.suppressions.len(), 1);
    assert_eq!(consumed.suppressions, borrowed.suppressions);

    let replayed = crate::report_from_file_analysis(consumed, "/test/sample.bin".into());
    assert_eq!(replayed.suppressions, borrowed.suppressions);
}

#[test]
fn scanner_catalog_self_hits_drop_only_that_files_yara_signatures() {
    let mut report = AnalysisReport::new(test_target());
    report.findings.push(test_finding(
        "well-known/tool/detection/malcontent::malcontent-defensive-scanner-context",
        Criticality::Exception,
    ));
    report.findings.push(test_finding(
        "third_party/elastic/Linux_Trojan_Mirai/linux/trojan/mirai",
        Criticality::Hostile,
    ));
    report.findings.push(test_finding(
        "objectives/evasion/kernel-hide/module::reptile-name",
        Criticality::Suspicious,
    ));
    report.findings.push(test_finding(
        "metadata/file/size::something",
        Criticality::Notable,
    ));
    let mut sibling = FileAnalysis::default();
    sibling.findings.push(test_finding(
        "third_party/elastic/Linux_Trojan_Mirai/linux/trojan/mirai",
        Criticality::Hostile,
    ));
    report.files.push(sibling);

    report.suppress_scanner_catalog_self_hits();

    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(
        ids.contains(&"well-known/tool/detection/malcontent::malcontent-defensive-scanner-context")
    );
    assert!(ids.contains(&"metadata/file/size::something"));
    assert!(!ids.iter().any(|id| id.starts_with("third_party/")));
    // The context is three strings any binary can embed; it excuses only the
    // catalog's own YARA self-hits, never native findings.
    assert!(ids.contains(&"objectives/evasion/kernel-hide/module::reptile-name"));
    assert_eq!(report.files[0].findings.len(), 1);
}

#[test]
fn clear_unserialized_member_fields_drops_strings_after_matching() {
    let string = StringInfo {
        value: "secret retained by old member pipeline".to_string().into(),
        offset: Some(7),
        encoding: "utf-8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    };
    let mut report = AnalysisReport::new(test_target());
    report.strings.push(string.clone());
    report.findings.push(test_finding(
        "behavior/member::matched",
        Criticality::Notable,
    ));
    let mut nested = FileAnalysis::new(
        1,
        "nested.js".to_string(),
        "javascript".to_string(),
        "nested-sha".to_string(),
        42,
    );
    nested.strings.push(string);
    nested.findings.push(test_finding(
        "behavior/nested::matched",
        Criticality::Suspicious,
    ));
    report.files.push(nested);

    report.clear_unserialized_member_fields();

    assert!(report.strings.is_empty());
    assert!(report.files[0].strings.is_empty());
    assert_eq!(report.findings.len(), 1, "matched traits remain");
    assert_eq!(
        report.files[0].findings.len(),
        1,
        "nested matched traits remain"
    );
}

/// Analysis appends findings as its producers finish; the output order must
/// not depend on that (the compact `uses` indexes into it).
#[test]
fn finalize_orders_findings_by_severity_then_id() {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/a.bin".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1,
        sha256: String::new(),
        architectures: None,
    });
    for (id, crit) in [
        ("m/b::two", Criticality::Notable),
        ("m/a::one", Criticality::Notable),
        ("m/z::bad", Criticality::Hostile),
    ] {
        let mut finding =
            Finding::new(id.to_string(), FindingKind::Capability, id.to_string(), 0.9);
        finding.crit = crit;
        report.findings.push(finding);
    }
    report.finalize();
    let ids: Vec<&str> = report.files[0]
        .findings
        .iter()
        .map(|f| f.id.as_str())
        .collect();
    assert_eq!(ids, ["m/z::bad", "m/a::one", "m/b::two"]);
}

/// A member's value-matched finding rolls up to its container with the
/// matcher's `value:<path>` label after the member name. It must still be
/// attributed to the member: an unsigned installer otherwise listed its signed
/// payload's signer record as its own.
#[test]
fn finalize_attributes_rolled_up_value_findings_to_their_member() {
    let id = "metadata/signature/certificate/subject::pe-signer-subject-record";
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/setup.exe".to_string(),
        file_type: "pe".to_string(),
        size_bytes: 100,
        sha256: "setup-sha".to_string(),
        architectures: None,
    });
    let mut rolled_up = Finding::new(id.to_string(), FindingKind::Capability, id.to_string(), 1.0);
    rolled_up.evidence.push(Evidence {
        method: "value".to_string(),
        source: "payload.exe".to_string(),
        value: "pe.signatures[0].subject".to_string(),
        location: Some("archive:payload.exe:value:pe.signatures[0].subject".to_string()),
        ..Default::default()
    });
    report.findings.push(rolled_up);
    let mut member = FileAnalysis::new(
        0,
        "payload.exe".to_string(),
        "pe".to_string(),
        "payload-sha".to_string(),
        42,
    );
    member.depth = 1;
    member.findings.push(Finding::new(
        id.to_string(),
        FindingKind::Capability,
        id.to_string(),
        1.0,
    ));
    report.files.push(member);

    report.finalize();

    let member_id = report.files[1].id;
    let root = report.files[0]
        .findings
        .iter()
        .find(|f| f.id == id)
        .expect("rolled-up finding stays listed on the container");
    assert_eq!(
        root.src,
        Some(member_id),
        "it is the member's, not the root's"
    );
}

#[test]
fn located_member_id_ignores_matcher_labels_after_the_member() {
    let members: rustc_hash::FxHashMap<String, u32> = [
        ("payload.exe".to_string(), 2),
        ("odd:name.txt".to_string(), 3),
    ]
    .into_iter()
    .collect();
    for (location, want) in [
        ("archive:payload.exe", Some(2)),
        ("archive:payload.exe:0x40", Some(2)),
        (
            "archive:payload.exe:value:pe.signatures[0].subject",
            Some(2),
        ),
        ("archive:payload.exe:offset:12", Some(2)),
        ("archive:outer.zip!!payload.exe:value:pe.machine", Some(2)),
        ("archive:odd:name.txt", Some(3)),
        ("archive:odd:name.txt:value:x", Some(3)),
        ("archive:other.exe:value:x", None),
        ("value:pe.signatures[0].subject", None),
    ] {
        assert_eq!(located_member_id(location, &members), want, "{location}");
    }
}

#[test]
fn finalize_rebases_a_local_nested_archive_chain_under_the_root() {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/bundle.zip".to_string(),
        file_type: "zip".to_string(),
        size_bytes: 100,
        sha256: "bundle-sha".to_string(),
        architectures: None,
    });
    let mut child = FileAnalysis::new(
        0,
        "setup.exe!!app/bin/payload.dll".to_string(),
        "pe".to_string(),
        "payload-sha".to_string(),
        42,
    );
    child.depth = 2;
    report.files.push(child);

    report.finalize();

    assert_eq!(
        report.files[1].path,
        "/samples/bundle.zip!!setup.exe!!app/bin/payload.dll"
    );
}

#[test]
fn finalize_rebases_decoded_archive_children_and_links_their_parent() {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/reference.tar.gz".to_string(),
        file_type: "tar.gz".to_string(),
        size_bytes: 100,
        sha256: "archive-sha".to_string(),
        architectures: None,
    });
    let mut member = FileAnalysis::new(
        0,
        "PayloadsAllTheThings-4.2/.github/hopla_config.json".to_string(),
        "json".to_string(),
        "member-sha".to_string(),
        42,
    );
    member.depth = 1;
    let mut decoded = FileAnalysis::new(
        1,
        "PayloadsAllTheThings-4.2/.github/hopla_config.json##base64@12728".to_string(),
        "php".to_string(),
        "decoded-sha".to_string(),
        50,
    );
    decoded.depth = 2;
    report.files.extend([member, decoded]);

    report.finalize();

    assert_eq!(
        report.files[1].path,
        "/samples/reference.tar.gz!!PayloadsAllTheThings-4.2/.github/hopla_config.json"
    );
    assert_eq!(
        report.files[2].path,
        "/samples/reference.tar.gz!!PayloadsAllTheThings-4.2/.github/hopla_config.json##base64@12728"
    );
    assert_eq!(report.files[2].parent_id, Some(1));
}

#[test]
fn finalize_links_embedded_file_in_decoded_root() {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/carrier.gif".into(),
        file_type: "gif".into(),
        size_bytes: 100,
        sha256: "carrier-sha".into(),
        architectures: None,
    });
    let mut decoded = FileAnalysis::new(
        0,
        "/samples/carrier.gif##base64@42".into(),
        "pe".into(),
        "pe-sha".into(),
        50,
    );
    decoded.depth = 1;
    let mut embedded = FileAnalysis::new(
        1,
        "/samples/carrier.gif##base64@42!!embedded:pe:payload.dll@7".into(),
        "pe".into(),
        "dll-sha".into(),
        20,
    );
    embedded.depth = 2;
    report.files.extend([decoded, embedded]);
    report.finalize();
    assert_eq!(
        report.files[2].path,
        "/samples/carrier.gif##base64@42!!embedded:pe:payload.dll@7"
    );
    assert_eq!(report.files[2].parent_id, Some(1));
}

/// An embedded image is filed under its host's local root (the ELF, PE and
/// generic analyzers name it `<host name>!!embedded:<kind>@<off>`); finalize
/// replaces that root with the full path instead of nesting the host under
/// itself (`manager!!manager!!embedded:elf@0x268cc60`, the Kong dropper).
#[test]
fn finalize_replaces_the_local_root_of_an_embedded_member() {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/kong/manager".into(),
        file_type: "elf".into(),
        size_bytes: 100,
        sha256: "host-sha".into(),
        architectures: None,
    });
    let mut embedded = FileAnalysis::new(
        0,
        "manager!!embedded:elf@0x268cc60".into(),
        "elf".into(),
        "child-sha".into(),
        50,
    );
    embedded.depth = 1;
    let mut nested = FileAnalysis::new(
        1,
        "manager!!embedded:elf@0x268cc60##base64@12".into(),
        "shell".into(),
        "nested-sha".into(),
        10,
    );
    nested.depth = 2;
    // A member whose name merely starts with the host's is not its root.
    let mut lookalike = FileAnalysis::new(
        2,
        "manager-config!!x".into(),
        "text".into(),
        "lookalike-sha".into(),
        5,
    );
    lookalike.depth = 1;
    report.files.extend([embedded, nested, lookalike]);

    report.finalize();

    assert_eq!(
        report.files[1].path,
        "/samples/kong/manager!!embedded:elf@0x268cc60"
    );
    assert_eq!(report.files[1].parent_id, Some(0));
    assert_eq!(
        report.files[2].path,
        "/samples/kong/manager!!embedded:elf@0x268cc60##base64@12"
    );
    assert_eq!(report.files[2].parent_id, Some(1));
    assert_eq!(
        report.files[3].path,
        "/samples/kong/manager!!manager-config!!x"
    );
}

fn local_ref(path: &str) -> filefacts::Reference {
    let mut reference = filefacts::Reference::new(
        filefacts::RefLocator::Path(path.to_string()),
        filefacts::RefKind::Local,
        "package.json:main",
        path,
    );
    reference.offset = Some(10);
    reference
}

fn dep_ref(purl: &str) -> filefacts::Reference {
    let mut reference = filefacts::Reference::new(
        filefacts::RefLocator::Purl(purl.to_string()),
        filefacts::RefKind::Dependency,
        "package.json",
        purl,
    );
    reference.offset = Some(20);
    reference
}

fn file_with_refs(id: u32, path: &str, refs: Vec<filefacts::Reference>) -> FileAnalysis {
    let mut f = FileAnalysis::new(id, path.to_string(), "json".into(), format!("sha{id}"), 100);
    f.filefacts = Some(FilefactsView {
        references: refs,
        ..Default::default()
    });
    f
}

fn named_identity(name: &str) -> filefacts::Identity {
    let mut identity = filefacts::Identity::default();
    identity.name = Some(filefacts::Claim::claimed(name, "test"));
    identity
}

#[test]
fn internal_reference_to_hostile_sibling_raises_neutral_metadata_fact() {
    let referrer = file_with_refs(
        0,
        "pkg.zip!!a/package.json",
        vec![local_ref("./payload.js")],
    );
    let mut payload = FileAnalysis::new(
        1,
        "pkg.zip!!a/payload.js".into(),
        "js".into(),
        "sha1".into(),
        50,
    );
    payload.findings = vec![test_finding("objectives/evil::x", Criticality::Hostile)];
    let mut files = vec![referrer, payload];

    AnalysisReport::link_flagged_references(&mut files);

    let f = &files[0];
    let linked = f
        .findings
        .iter()
        .find(|fd| fd.id == "metadata/relationship::references-flagged-component")
        .expect("internal edge finding");
    // Neutral — references the bad sibling, doesn't inherit its severity.
    assert_eq!(linked.crit, Criticality::Baseline);
    assert_eq!(
        f.composite_sources[linked.id.as_str()][0].file,
        1,
        "trail names the sibling"
    );
}

#[test]
fn external_dependency_on_hostile_vendored_member_propagates_one_below() {
    let referrer = file_with_refs(
        0,
        "pkg.zip!!package.json",
        vec![dep_ref("pkg:npm/evil@1.0.0")],
    );
    // The dependency is vendored in the bundle and scored hostile.
    let mut vendored = file_with_refs(1, "pkg.zip!!node_modules/evil/index.js", vec![]);
    vendored.identity = Some(named_identity("evil"));
    vendored.findings = vec![test_finding(
        "well-known/malware/x::y",
        Criticality::Hostile,
    )];
    let mut files = vec![referrer, vendored];

    AnalysisReport::link_flagged_references(&mut files);

    let f = &files[0];
    let linked = f
        .findings
        .iter()
        .find(|fd| {
            fd.id == "objectives/supply-chain/malicious-dependency::references-malicious-component"
        })
        .expect("supply-chain finding");
    // Hostile target → suspicious referrer (one criticality below).
    assert_eq!(linked.crit, Criticality::Suspicious);
    assert!(
        linked.desc.contains("evil"),
        "names the dependency: {}",
        linked.desc
    );
    assert_eq!(f.composite_sources[linked.id.as_str()][0].file, 1);
}

#[test]
fn reference_to_benign_file_raises_nothing() {
    let referrer = file_with_refs(0, "pkg.zip!!a/package.json", vec![local_ref("./helper.js")]);
    let mut helper = FileAnalysis::new(
        1,
        "pkg.zip!!a/helper.js".into(),
        "js".into(),
        "sha1".into(),
        50,
    );
    helper.findings = vec![test_finding("net/socket", Criticality::Notable)]; // below suspicious
    let mut files = vec![referrer, helper];

    AnalysisReport::link_flagged_references(&mut files);

    assert!(
        files[0].findings.is_empty(),
        "a notable target is not flagged, so no reference finding"
    );
}

#[test]
fn strip_unmatched_traits_drops_only_unreferenced_components_and_baselines() {
    let mut report = AnalysisReport::new(test_target());
    let mut file = FileAnalysis::new(0, "/sample.bin".into(), "elf".into(), "abc123".into(), 1024);

    // A fired composite names one component and one baseline by id; those two
    // are kept despite their low criticality, the unreferenced twins are not,
    // and the notable is untouched regardless of references.
    let mut composite = test_finding("objectives/x::y", Criticality::Hostile);
    composite.trait_refs = vec!["comp/used".into(), "base/used".into()];
    file.findings = vec![
        composite,
        test_finding("comp/used", Criticality::Component),
        test_finding("comp/orphan", Criticality::Component),
        test_finding("base/used", Criticality::Baseline),
        test_finding("base/orphan", Criticality::Baseline),
        test_finding("note/keep", Criticality::Notable),
    ];
    report.files = vec![file];

    let (components, baselines) = report.strip_unmatched_traits();
    assert_eq!(components, 1, "one unreferenced component dropped");
    assert_eq!(baselines, 1, "one unreferenced baseline dropped");

    let kept: Vec<&str> = report.files[0]
        .findings
        .iter()
        .map(|f| f.id.as_str())
        .collect();
    assert_eq!(kept.len(), 4);
    for id in ["objectives/x::y", "comp/used", "base/used", "note/keep"] {
        assert!(kept.contains(&id), "{id} should be kept");
    }
    for id in ["comp/orphan", "base/orphan"] {
        assert!(!kept.contains(&id), "{id} should be stripped");
    }

    // Idempotent: a second pass removes nothing.
    assert_eq!(report.strip_unmatched_traits(), (0, 0));
}

#[test]
fn strip_unmatched_traits_rescues_best_low_tier_when_no_signal() {
    let mut report = AnalysisReport::new(test_target());
    let mut file = FileAnalysis::new(0, "/quiet.bin".into(), "elf".into(), "abc123".into(), 1024);

    // No notable-or-higher finding: every trait would normally be stripped.
    // Confidence orders the rescue, so the three highest-confidence survive.
    let mut findings = Vec::new();
    for (i, conf) in [0.1f32, 0.9, 0.5, 0.7, 0.3].iter().enumerate() {
        let mut f = test_finding(&format!("base/t{i}"), Criticality::Baseline);
        f.conf = *conf;
        findings.push(f);
    }
    file.findings = findings;
    report.files = vec![file];

    let (components, baselines) = report.strip_unmatched_traits();
    assert_eq!(components, 0);
    assert_eq!(baselines, 2, "five low-tier traits, three rescued");

    let kept: Vec<&str> = report.files[0]
        .findings
        .iter()
        .map(|f| f.id.as_str())
        .collect();
    assert_eq!(kept.len(), RESCUE_LOW_TIER_KEEP);
    // t1 (0.9), t3 (0.7), t2 (0.5) win; t4 (0.3) and t0 (0.1) drop.
    for id in ["base/t1", "base/t3", "base/t2"] {
        assert!(kept.contains(&id), "{id} should be rescued");
    }
    for id in ["base/t0", "base/t4"] {
        assert!(!kept.contains(&id), "{id} should be stripped");
    }
}

#[test]
fn strip_unmatched_traits_no_rescue_when_signal_present() {
    let mut report = AnalysisReport::new(test_target());
    let mut file = FileAnalysis::new(0, "/loud.bin".into(), "elf".into(), "abc123".into(), 1024);

    // A lone notable counts as signal, so the low-tier traits strip in full.
    file.findings = vec![
        test_finding("note/keep", Criticality::Notable),
        test_finding("base/a", Criticality::Baseline),
        test_finding("comp/b", Criticality::Component),
    ];
    report.files = vec![file];

    let (components, baselines) = report.strip_unmatched_traits();
    assert_eq!((components, baselines), (1, 1));
    let kept: Vec<&str> = report.files[0]
        .findings
        .iter()
        .map(|f| f.id.as_str())
        .collect();
    assert_eq!(kept, vec!["note/keep"]);
}

#[test]
fn graft_findings_places_on_target_and_strip_preserves_cross_node_members() {
    // The fetch-driven package pass: a composite correlating a fetched
    // artifact with its registry metadata is grafted onto the artifact node,
    // but its building-block traits live on two *different* nodes (the
    // native-addon trait on the artifact, the deprecated trait on the
    // registry document). `strip_unmatched_traits` unions `trait_refs`
    // across every node, so both survive even though neither shares a node
    // with the grafted composite. This is the step that silently breaks if
    // graft attribution regresses.
    let mut report = AnalysisReport::new(test_target());
    let mut artifact = FileAnalysis::new(
        0,
        "/pkg.whl".into(),
        "zip".into(),
        "artifactsha".into(),
        2048,
    );
    artifact.findings = vec![test_finding(
        "test/pkg::native-addon",
        Criticality::Component,
    )];
    let mut registry = FileAnalysis::new(
        1,
        "/pkg.registry.json".into(),
        "registry".into(),
        "registrysha".into(),
        256,
    );
    registry.findings = vec![test_finding("test/pkg::deprecated", Criticality::Component)];
    report.files = vec![artifact, registry];

    // Graft the package composite onto the artifact node, carrying both
    // members in `trait_refs` (as `CompositeTrait::evaluate` does).
    let mut composite = test_finding("test/pkg::deprecated-with-addon", Criticality::Suspicious);
    composite.trait_refs = vec![
        "test/pkg::native-addon".into(),
        "test/pkg::deprecated".into(),
    ];
    assert_eq!(report.graft_findings("artifactsha", vec![composite]), 1);
    // Landed on the artifact node, not the registry node.
    assert!(
        report.files[0]
            .findings
            .iter()
            .any(|f| f.id == "test/pkg::deprecated-with-addon"),
        "composite should graft onto the artifact node"
    );

    let (components, baselines) = report.strip_unmatched_traits();
    assert_eq!(
        (components, baselines),
        (0, 0),
        "both component members are referenced by the grafted composite, so none strip"
    );
    assert!(
        report.files[1]
            .findings
            .iter()
            .any(|f| f.id == "test/pkg::deprecated"),
        "the registry building-block trait must survive on its own node"
    );

    // A second graft of the same id is deduped (returns 0).
    let dup = test_finding("test/pkg::deprecated-with-addon", Criticality::Suspicious);
    assert_eq!(report.graft_findings("artifactsha", vec![dup]), 0);
    // Grafting onto a sha that isn't present is a no-op.
    assert_eq!(
        report.graft_findings(
            "nosuchsha",
            vec![test_finding("x::y", Criticality::Notable)]
        ),
        0
    );
}

#[test]
fn attach_composite_sources_ties_composite_to_members_with_locations() {
    use super::super::file_analysis::ARCHIVE_DELIMITER;
    use super::super::traits_findings::ContextLine;

    // Container with a cross-file composite referencing two components.
    let mut container = FileAnalysis::new(0, "/x.tgz".into(), "tar.gz".into(), "s0".into(), 100);
    let mut composite = test_finding(
        "objectives/supply-chain/dropper::implant",
        Criticality::Hostile,
    );
    composite.trait_refs = vec!["comp/manifest".into(), "comp/payload".into()];
    container.findings = vec![composite];

    // Member 1: a manifest carrying comp/manifest, anchored to a source line.
    let mut m1 = FileAnalysis::new(
        1,
        format!("/x.tgz{ARCHIVE_DELIMITER}pkg/manifest.json"),
        "json".into(),
        "s1".into(),
        10,
    );
    m1.depth = 1;
    m1.findings = vec![test_finding("comp/manifest", Criticality::Component)];
    m1.findings[0].precomputed_spans = Some(vec![[40, 5]]);
    m1.context = vec![ContextLine {
        loc: 40, // byte offset of the chunk start
        line: Some(3),
        col: Some(1),
        data: b"  \"preinstall\": \"node x\"".to_vec(),
    }];

    // Member 2: a binary carrying comp/payload, anchored to a byte offset.
    let mut m2 = FileAnalysis::new(
        2,
        format!("/x.tgz{ARCHIVE_DELIMITER}pkg/bin"),
        "elf".into(),
        "s2".into(),
        20,
    );
    m2.depth = 1;
    m2.findings = vec![test_finding("comp/payload", Criticality::Suspicious)];
    m2.findings[0].precomputed_spans = Some(vec![[0x1234, 4]]);
    m2.context = vec![ContextLine {
        loc: 0x1234,
        line: None, // byte-addressed (binary) → no source line/col
        col: None,
        data: vec![0u8; 4],
    }];

    let mut files = vec![container, m1, m2];
    AnalysisReport::attach_composite_sources(&mut files);

    let sources = files[0]
        .composite_sources
        .get("objectives/supply-chain/dropper::implant")
        .expect("composite resolved to sources");
    assert_eq!(sources.len(), 2, "both contributing members tracked");
    let s1 = sources
        .iter()
        .find(|s| s.file == 1)
        .expect("manifest member");
    assert_eq!(s1.line, Some(3), "source component carries its line");
    assert_eq!(s1.offset, Some(40));
    let s2 = sources.iter().find(|s| s.file == 2).expect("binary member");
    assert_eq!(s2.line, None, "binary component has no source line");
    assert_eq!(
        s2.offset,
        Some(0x1234),
        "binary component carries its offset"
    );
}

#[test]
fn attach_composite_sources_chooses_earliest_evidence_independent_of_input_order() {
    use super::super::file_analysis::ARCHIVE_DELIMITER;
    use super::super::traits_findings::ContextLine;

    let run = |refs: &[&str], reverse_context: bool| {
        let mut container =
            FileAnalysis::new(0, "/x.tgz".into(), "tar.gz".into(), "s0".into(), 100);
        let mut composite = test_finding("test/archive::aggregate", Criticality::Notable);
        composite.trait_refs = refs.iter().map(|id| (*id).into()).collect();
        container.findings = vec![composite];

        let mut member = FileAnalysis::new(
            1,
            format!("/x.tgz{ARCHIVE_DELIMITER}pkg/index.js"),
            "javascript".into(),
            "s1".into(),
            100,
        );
        member.depth = 1;
        member.findings = vec![
            test_finding("comp/path-z", Criticality::Component),
            test_finding("comp/path-a", Criticality::Component),
        ];
        member.findings[0].precomputed_spans = Some(vec![[80, 5]]);
        member.findings[1].precomputed_spans = Some(vec![[20, 5]]);
        let earlier = ContextLine {
            loc: 10,
            line: Some(2),
            col: Some(1),
            data: b"first path: a/b".to_vec(),
        };
        let later = ContextLine {
            loc: 70,
            line: Some(5),
            col: Some(1),
            data: b"second path".to_vec(),
        };
        member.context = if reverse_context {
            vec![later, earlier]
        } else {
            vec![earlier, later]
        };

        let mut files = vec![container, member];
        AnalysisReport::attach_composite_sources(&mut files);
        files[0].composite_sources["test/archive::aggregate"][0].clone()
    };

    let later_first = run(&["comp/path-z", "comp/path-a"], true);
    let earlier_first = run(&["comp/path-a", "comp/path-z"], false);
    assert_eq!(later_first.offset, Some(20));
    assert_eq!(later_first.line, Some(2));
    assert_eq!(earlier_first.offset, Some(20));
    assert_eq!(earlier_first.line, Some(2));
}

#[test]
fn graft_reattaches_sources_across_member_and_registry_child() {
    // The fetch pass shape: a package-scoped composite grafted onto the
    // artifact node after finalize, whose legs live on (a) an archive member
    // and (b) a grafted `registry` child that is NOT under the container's
    // archive path (linked by `parent_id`). Grafting must re-resolve sources
    // so both legs surface — the member by path, the registry leg by parent.
    use super::super::file_analysis::ARCHIVE_DELIMITER;
    use super::super::traits_findings::ContextLine;

    let mut report = AnalysisReport::new(test_target());

    // Artifact/container node (the graft target).
    let mut artifact = FileAnalysis::new(
        0,
        "/pkg.tgz".into(),
        "tar.gz".into(),
        "artifactsha".into(),
        100,
    );
    artifact.findings = vec![];

    // Archive member carrying the code leg, anchored to a source line.
    let mut member = FileAnalysis::new(
        1,
        format!("/pkg.tgz{ARCHIVE_DELIMITER}pkg/install.js"),
        "javascript".into(),
        "membersha".into(),
        20,
    );
    member.parent_id = Some(0);
    member.depth = 1;
    member.findings = vec![test_finding(
        "objectives/exfiltration::post",
        Criticality::Component,
    )];
    member.findings[0].precomputed_spans = Some(vec![[200, 5]]);
    member.context = vec![ContextLine {
        loc: 200,
        line: Some(12),
        col: Some(1),
        data: b"fetch(url, {method:'POST'})".to_vec(),
    }];

    // Registry provenance child: a direct child of the artifact by parent_id,
    // path is the synthetic registry doc name (NOT under the archive prefix).
    let mut registry = FileAnalysis::new(
        2,
        "be5invis_iosevka.registry.json".into(),
        "registry".into(),
        "regsha".into(),
        64,
    );
    registry.parent_id = Some(0);
    registry.depth = 1;
    registry.findings = vec![test_finding(
        "metadata/registry::freshly-published",
        Criticality::Notable,
    )];

    report.files = vec![artifact, member, registry];

    // Graft the package composite carrying both legs in trait_refs.
    let mut composite = test_finding("supply-chain::obfuscated-exfil", Criticality::Hostile);
    composite.trait_refs = vec![
        "objectives/exfiltration::post".into(),
        "metadata/registry::freshly-published".into(),
    ];
    assert_eq!(report.graft_findings("artifactsha", vec![composite]), 1);

    // The graft must have re-run source attribution: the composite now trails
    // both its member (code) leg and its registry (provenance) child.
    let sources = report.files[0]
        .composite_sources
        .get("supply-chain::obfuscated-exfil")
        .expect("graft re-attached composite sources");
    assert!(
        sources.iter().any(|s| s.file == 1 && s.line == Some(12)),
        "archive-member code leg tracked with its line, got: {sources:?}"
    );
    assert!(
        sources.iter().any(|s| s.file == 2),
        "registry provenance child tracked via parent_id, got: {sources:?}"
    );
}

// ==================== Criticality Tests ====================

#[test]
fn test_criticality_ordering() {
    assert!(Criticality::Filtered < Criticality::Exception);
    assert!(Criticality::Exception < Criticality::Component);
    assert!(Criticality::Component < Criticality::Baseline);
    assert!(Criticality::Baseline < Criticality::Notable);
    assert!(Criticality::Notable < Criticality::Suspicious);
    assert!(Criticality::Suspicious < Criticality::Hostile);
    // The load-bearing invariant: an exception is never positive signal, so
    // every `crit >= Notable` gate excludes it.
    assert!(Criticality::Exception < Criticality::Notable);
}

#[test]
fn test_criticality_exception_serde_roundtrip() {
    // serde uses the lowercase variant name; `crit: exception` must parse.
    let json = serde_json::to_string(&Criticality::Exception).unwrap();
    assert_eq!(json, "\"exception\"");
    let parsed: Criticality = serde_json::from_str("\"exception\"").unwrap();
    assert_eq!(parsed, Criticality::Exception);
}

#[test]
fn test_criticality_max() {
    let crits = vec![
        Criticality::Baseline,
        Criticality::Hostile,
        Criticality::Notable,
    ];
    assert_eq!(crits.into_iter().max(), Some(Criticality::Hostile));
}

#[test]
fn test_criticality_default() {
    assert_eq!(Criticality::default(), Criticality::Baseline);
}

#[test]
fn test_criticality_equality() {
    assert_eq!(Criticality::Hostile, Criticality::Hostile);
    assert_ne!(Criticality::Hostile, Criticality::Suspicious);
}

// ==================== AnalysisReport::new Tests ====================

#[test]
fn test_analysis_report_new() {
    let report = AnalysisReport::new(test_target());

    assert_eq!(report.version, "3.0");
    assert_eq!(report.target.path, "/test/sample.bin");
    assert!(report.findings.is_empty());
    assert!(report.traits.is_empty());
    assert!(report.strings.is_empty());
}

#[test]
fn test_analysis_report_new_with_timestamp() {
    use chrono::TimeZone;
    let ts = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
    let report = AnalysisReport::new_with_timestamp(test_target(), ts);

    assert_eq!(report.analysis_timestamp, Some(ts));
}

// ==================== add_finding Tests ====================

#[test]
fn test_add_finding_basic() {
    let mut report = AnalysisReport::new(test_target());
    let finding = test_finding("test/cap1", Criticality::Notable);

    report.add_finding(finding);

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].id, "test/cap1");
}

#[test]
fn test_add_finding_dedup() {
    let mut report = AnalysisReport::new(test_target());

    report.add_finding(test_finding("test/cap1", Criticality::Notable));
    report.add_finding(test_finding("test/cap1", Criticality::Hostile)); // Same ID

    // Should deduplicate - only one finding
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn test_add_finding_different_ids() {
    let mut report = AnalysisReport::new(test_target());

    report.add_finding(test_finding("test/cap1", Criticality::Notable));
    report.add_finding(test_finding("test/cap2", Criticality::Hostile));

    assert_eq!(report.findings.len(), 2);
}

// ==================== highest_criticality Tests ====================

// ==================== TargetInfo Tests ====================

#[test]
fn test_target_info_creation() {
    let target = TargetInfo {
        path: "/path/to/file".to_string(),
        file_type: "macho".to_string(),
        size_bytes: 2048,
        sha256: "deadbeef".to_string(),
        architectures: Some(vec!["arm64".to_string(), "x86_64".to_string()]),
    };

    assert_eq!(target.path, "/path/to/file");
    assert_eq!(target.file_type, "macho");
    assert_eq!(target.size_bytes, 2048);
    assert_eq!(target.architectures.as_ref().unwrap().len(), 2);
}

#[test]
fn test_target_info_no_architectures() {
    let target = TargetInfo {
        path: "/path/to/script.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: 512,
        sha256: "abc123".to_string(),
        architectures: None,
    };

    assert!(target.architectures.is_none());
}

// ==================== ArchiveEntry Tests ====================

#[test]
fn test_archive_entry_simple_path() {
    let entry = ArchiveEntry {
        path: "lib/utils.so".to_string(),
        file_type: "elf".to_string(),
        sha256: "abc123".to_string(),
        size_bytes: 4096,
        ..ArchiveEntry::default()
    };

    assert_eq!(entry.path, "lib/utils.so");
    assert!(!entry.path.contains('!'));
}

#[test]
fn test_archive_entry_nested_path() {
    let entry = ArchiveEntry {
        path: "inner.tar.gz!malware/script.sh".to_string(),
        file_type: "shell".to_string(),
        sha256: "def456".to_string(),
        size_bytes: 256,
        ..ArchiveEntry::default()
    };

    assert!(entry.path.contains('!'));
}

// ==================== wrapper inheritance Tests ====================

fn test_file(path: &str, findings: Vec<Finding>) -> FileAnalysis {
    let mut fa = FileAnalysis::new(
        0,
        path.to_string(),
        "macho".to_string(),
        "sha256hash".to_string(),
        1024,
    );
    fa.findings = findings;
    fa.compute_summary();
    fa
}

#[test]
fn test_inherit_archive_child_findings_preserves_child() {
    let mut report = AnalysisReport::new(test_target());
    report.files = vec![
        test_file(
            "/archive.zip",
            vec![test_finding("cap/archive", Criticality::Notable)],
        ),
        test_file(
            "/archive.zip!!member.py",
            vec![test_finding("cap/member", Criticality::Suspicious)],
        ),
    ];

    report.files[1].id = 1;

    let changed = report.inherit_child_findings_into_wrappers();

    assert_eq!(changed, vec![0]);
    assert_eq!(report.files.len(), 2);
    // The wrapper's own finding stays native; the bubbled-up one is tagged
    // with the member's file id so it can be attributed back to its origin.
    let archive = report.files[0]
        .findings
        .iter()
        .find(|f| f.id == "cap/archive")
        .expect("wrapper keeps its own finding");
    assert_eq!(archive.src, None, "native finding is not tagged");
    let inherited = report.files[0]
        .findings
        .iter()
        .find(|f| f.id == "cap/member")
        .expect("member finding bubbled up");
    assert_eq!(inherited.src, Some(1), "inherited finding points at member");
    // The child entry is preserved and its own copy stays native.
    assert_eq!(report.files[1].findings.len(), 1);
    assert_eq!(report.files[1].findings[0].id, "cap/member");
    assert_eq!(report.files[1].findings[0].src, None);
}

#[test]
fn located_member_matches_leaf_member() {
    // Evidence locations carry the bare member name (plus an optional offset),
    // while file paths carry the full archive chain — both reduce to the same
    // leaf member, which is how provenance is matched in `finalize`.
    assert_eq!(located_member("archive:embedded_ls"), Some("embedded_ls"));
    assert_eq!(
        located_member("archive:embedded_ls:0x1126"),
        Some("embedded_ls")
    );
    assert_eq!(located_member("archive:lib/foo.so"), Some("lib/foo.so"));
    assert_eq!(located_member("offset:0x40"), None);
    assert_eq!(located_member("import"), None);
    assert_eq!(leaf_member("/tmp/a.zip!!embedded_ls"), "embedded_ls");
    assert_eq!(leaf_member("/tmp/a.zip!!inner.zip!!deep"), "deep");
    assert_eq!(leaf_member("/bin/ls"), "/bin/ls");
}

#[test]
fn test_inherit_nested_child_findings_to_each_wrapper() {
    let mut report = AnalysisReport::new(test_target());
    report.files = vec![
        test_file(
            "/outer.zip",
            vec![test_finding("cap/outer", Criticality::Notable)],
        ),
        test_file(
            "/outer.zip!!inner.tar",
            vec![test_finding("cap/inner", Criticality::Notable)],
        ),
        test_file(
            "/outer.zip!!inner.tar!!payload",
            vec![test_finding("cap/payload", Criticality::Hostile)],
        ),
    ];
    report.files[1].depth = 1;
    report.files[2].depth = 2;

    let changed = report.inherit_child_findings_into_wrappers();

    assert_eq!(changed, vec![0, 1]);
    assert!(
        report.files[1]
            .findings
            .iter()
            .any(|f| f.id == "cap/payload")
    );
    assert!(
        report.files[0]
            .findings
            .iter()
            .any(|f| f.id == "cap/payload")
    );
}

#[test]
fn test_finalize_inherits_upx_child_findings_into_root() {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/bin/sample".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 10,
        sha256: "rootsha".to_string(),
        architectures: None,
    });
    report.findings = vec![test_finding("anti-static/packer/upx", Criticality::Notable)];
    let mut child = test_file(
        "/bin/sample!!upx@0",
        vec![test_finding("cap/unpacked", Criticality::Suspicious)],
    );
    child.depth = 1;
    report.files.push(child);

    report.finalize();

    assert_eq!(report.files.len(), 2);
    assert_eq!(report.files[0].path, "/bin/sample");
    assert!(
        report.files[0]
            .findings
            .iter()
            .any(|f| f.id == "anti-static/packer/upx")
    );
    assert!(
        report.files[0]
            .findings
            .iter()
            .any(|f| f.id == "cap/unpacked")
    );
    assert!(
        report.files[1]
            .findings
            .iter()
            .any(|f| f.id == "cap/unpacked")
    );
}

// ==================== prune_archive_directories ====================

fn archive_report_with_entries(entries: Vec<ArchiveEntry>) -> AnalysisReport {
    let target = TargetInfo {
        path: "test.zip".to_string(),
        file_type: "zip".to_string(),
        size_bytes: 1024,
        sha256: "abc".to_string(),
        architectures: None,
    };
    let mut report = AnalysisReport::new(target);
    report.archive_contents = entries;
    report
}

#[test]
fn prune_archive_directories_keeps_only_members_with_content() {
    let dir = ArchiveEntry {
        path: "pkg/".to_string(),
        entry_type: Some("directory".to_string()),
        ..Default::default()
    };
    let file = ArchiveEntry {
        path: "pkg/a.js".to_string(),
        ..Default::default()
    };
    let mut report = archive_report_with_entries(vec![dir, file]);
    report.prune_archive_directories();
    let paths: Vec<_> = report
        .archive_contents
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(paths, ["pkg/a.js"]);
    assert!(report.values_tree.is_none());
}

#[test]
fn carrier_inheritance_uses_explicit_links_without_path_delimiters() {
    let mut report = AnalysisReport::new(test_target());
    let mut root = test_file("opaque-root", vec![]);
    root.id = 10;
    let mut child = test_file(
        "opaque-child",
        vec![test_finding("cap/payload", Criticality::Hostile)],
    );
    child.id = 20;
    child.parent_id = Some(10);
    child.depth = 1;
    let mut unrelated = test_file("opaque-unrelated", vec![]);
    unrelated.id = 30;
    report.files = vec![root, child, unrelated];
    assert_eq!(report.inherit_child_findings_into_wrappers(), vec![0]);
    let finding = &report.files[0].findings[0];
    assert_eq!(finding.id, "cap/payload");
    assert_eq!(finding.src, Some(20));
    assert!(report.files[2].findings.is_empty());
}

#[test]
fn carrier_local_root_paths_are_rebased_for_every_file_type() {
    for kind in crate::composite_rules::FileType::all_concrete_variants() {
        let kind = serde_json::to_value(kind)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/samples/carrier".to_string(),
            file_type: kind.to_string(),
            size_bytes: 100,
            sha256: "root".to_string(),
            architectures: None,
        });
        let mut child = test_file(
            "carrier!!payload",
            vec![test_finding("cap/payload", Criticality::Hostile)],
        );
        child.depth = 1;
        report.files.push(child);
        report.finalize();
        assert_eq!(report.files[1].path, "/samples/carrier!!payload", "{kind}");
        assert_eq!(report.files[1].parent_id, Some(0), "{kind}");
        assert!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id == "cap/payload" && f.src == Some(1)),
            "{kind}"
        );
    }
}

#[test]
fn carrier_rebase_preserves_real_member_named_after_root() {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/carrier".to_string(),
        file_type: "zip".to_string(),
        size_bytes: 100,
        sha256: "root".to_string(),
        architectures: None,
    });
    let mut inner = test_file("carrier", vec![]);
    inner.depth = 1;
    let mut payload = test_file(
        "carrier!!payload",
        vec![test_finding("cap/payload", Criticality::Hostile)],
    );
    payload.depth = 2;
    report.files = vec![inner, payload];
    report.finalize();
    assert_eq!(report.files[1].path, "/samples/carrier!!carrier");
    assert_eq!(report.files[2].path, "/samples/carrier!!carrier!!payload");
    assert_eq!(report.files[2].parent_id, Some(1));
    assert!(
        report.files[0]
            .findings
            .iter()
            .any(|f| f.id == "cap/payload")
    );
}
