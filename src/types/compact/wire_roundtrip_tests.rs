#[test]
fn dirty_revision_keeps_full_content_hash() {
    assert_eq!(super::wire_traits_version("9a6092f79".into()), "9a609");
    assert_eq!(
        super::wire_traits_version("wc138fe08c4d2a0e1".into()),
        "wc138fe08c4d2a0e1"
    );
}

/// A member whose facts were projected at fold time must convert to the
/// same CompactFile as one converted directly — same function either way,
/// pinned so a future divergence fails instead of silently changing output.
#[test]
fn precompacted_member_converts_identically() {
    let mut fa = crate::FileAnalysis {
        id: 1,
        path: "pkg.zip!!lib.dll".to_string(),
        file_type: "pe".to_string(),
        sha256: "a".repeat(64),
        size: 4096,
        depth: 1,
        ..Default::default()
    };
    fa.imports = vec![crate::types::Import {
        symbol: "CreateProcessW".to_string(),
        library: Some("kernel32.dll".to_string()),
        ..Default::default()
    }];
    fa.filefacts_metrics = Some(std::collections::BTreeMap::from([(
        "file.entropy".to_string(),
        7.123_456,
    )]));

    let direct = compact_from_files(&[fa.clone()], Facts::Full);

    let mut folded = fa;
    // Mirror `precompact_member_facts`: metrics stay flat until convert.
    folded.precompact_facts = Some(compact_facts_from_parts(&folded, false));
    folded.imports = Vec::new();
    let via_fold = compact_from_files(&[folded], Facts::Full);

    assert_eq!(
        serde_json::to_value(&direct).expect("direct"),
        serde_json::to_value(&via_fold).expect("folded"),
        "fold-time projection must not change the compact output"
    );
}
use super::*;

/// Encode with the hand-written `Serialize`, decode with the hand-written
/// `Deserialize`, and require the wire form to be stable across the round
/// trip. These encoders emit *positional, variable-length* tuples, so a
/// decoder that mis-orders or mis-counts elements is silently wrong rather
/// than an error — which would corrupt ML features, not crash. Re-encoding
/// and comparing JSON catches that.
fn roundtrip<T>(value: &T) -> serde_json::Value
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let encoded = serde_json::to_value(value).expect("encode");
    let decoded: T = serde_json::from_value(encoded.clone()).expect("decode");
    let re_encoded = serde_json::to_value(&decoded).expect("re-encode");
    assert_eq!(encoded, re_encoded, "wire form changed across round trip");
    encoded
}

#[test]
fn import_roundtrips_with_and_without_ordinal() {
    let short = roundtrip(&CompactImport {
        library: "kernel32.dll".into(),
        name: "VirtualAlloc".into(),
        ordinal: None,
    });
    assert_eq!(short, serde_json::json!(["kernel32.dll", "VirtualAlloc"]));

    let long = roundtrip(&CompactImport {
        library: "ws2_32.dll".into(),
        name: "connect".into(),
        ordinal: Some(4),
    });
    assert_eq!(long, serde_json::json!(["ws2_32.dll", "connect", 4]));
}

#[test]
fn export_roundtrips_with_and_without_forward() {
    assert_eq!(
        roundtrip(&CompactExport {
            name: "start".into(),
            forward_to: None,
        }),
        serde_json::json!(["start"])
    );
    assert_eq!(
        roundtrip(&CompactExport {
            name: "puts".into(),
            forward_to: Some("msvcrt.puts".into()),
        }),
        serde_json::json!(["puts", "msvcrt.puts"])
    );
}

/// `offset` is positionally before `kind`, so a function carrying a kind
/// always carries an offset slot too — the decoder must not read the kind
/// string into the offset.
#[test]
fn function_roundtrips_at_each_arity() {
    assert_eq!(
        roundtrip(&CompactFunction {
            name: "main".into(),
            offset: None,
            kind: None,
        }),
        serde_json::json!(["main"])
    );
    assert_eq!(
        roundtrip(&CompactFunction {
            name: "main".into(),
            offset: Some(4096),
            kind: None,
        }),
        serde_json::json!(["main", 4096])
    );
    assert_eq!(
        roundtrip(&CompactFunction {
            name: "main".into(),
            offset: Some(4096),
            kind: Some("export".into()),
        }),
        serde_json::json!(["main", 4096, "export"])
    );
}

#[test]
fn section_roundtrips_all_five_positions() {
    assert_eq!(
        roundtrip(&CompactSection {
            name: ".text".into(),
            offset: 1024,
            size: 2048,
            entropy: 6.5,
            flags: "rx".into(),
        }),
        serde_json::json!([".text", 1024, 2048, 6.5, "rx"])
    );
}

/// The whole point of the decoders: a real report, built the way emit
/// builds one, must survive the wire round trip byte-for-byte. This is the
/// guarantee the typed featurizer depends on — if it does not hold, reading
/// a report typed instead of as a `serde_json::Value` would silently change
/// ML features rather than fail.
/// `scan` marks an archive member it listed but never analyzed with
/// `risk: -1`. That is a real value on the wire, so the typed schema must
/// accept it — with `risk: u32` this input failed to deserialize outright,
/// and the other round-trip tests missed it because their fixtures were
/// all non-negative.
#[test]
fn negative_risk_sentinel_roundtrips() {
    let wire = serde_json::json!({
        "v": "8",
        "files": [{
            "id": 1, "path": "a.zip!!m.bin", "type": "data",
            "sha": "b".repeat(64), "size": 10, "depth": 1, "risk": -1
        }]
    });
    let decoded: CompactReport =
        serde_json::from_value(wire).expect("unanalyzed-member report must decode");
    assert_eq!(decoded.files[0].risk, -1);
    let re = serde_json::to_value(&decoded).expect("re-encode");
    assert_eq!(re["files"][0]["risk"], serde_json::json!(-1));
}

#[test]
fn composite_uses_indexes_its_components_in_this_file() {
    use super::super::file_analysis::FileAnalysis;
    use super::super::traits_findings::Finding;
    use super::super::{Criticality, FindingKind};

    fn trait_finding(id: &str, crit: Criticality, refs: &[&str]) -> Finding {
        let mut f = Finding::new(id, FindingKind::Capability, id, 0.9);
        f.crit = crit;
        f.trait_refs = refs.iter().map(|r| (*r).into()).collect();
        f
    }

    let mut fa = FileAnalysis::new(
        0,
        "shortcut.lnk".to_string(),
        "lnk".to_string(),
        "a".repeat(64),
        2048,
    );
    // Emission order deliberately puts a composite before one of its own
    // components, and chains a composite onto another composite: both are
    // shapes the single-pass fold cannot resolve on its own.
    fa.findings = vec![
        trait_finding("t/atomic::target", Criticality::Component, &[]),
        trait_finding(
            "t/comp::target-with-args",
            Criticality::Notable,
            &["t/atomic::target", "t/atomic::args"],
        ),
        trait_finding("t/atomic::args", Criticality::Component, &[]),
        trait_finding(
            "t/comp::chained",
            Criticality::Suspicious,
            &["t/comp::target-with-args", "t/elsewhere::member-leg"],
        ),
    ];

    let report = compact_from_files(&[fa], Facts::Full);
    let traits = &report.files[0].findings;

    assert!(traits[0].uses.is_empty(), "an atomic trait uses nothing");
    assert_eq!(
        traits[1].uses,
        vec![0, 2],
        "a composite must index both components, including one folded after it",
    );
    assert!(traits[2].uses.is_empty());
    assert_eq!(
        traits[3].uses,
        vec![1],
        "a composite leg that is itself a composite must resolve; a leg \
             living in another file must be dropped, not left dangling",
    );
    for t in traits {
        assert!(
            t.uses.iter().all(|i| (*i as usize) < traits.len()),
            "every index must address this file's traits[]",
        );
    }

    let encoded = serde_json::to_string(&report).expect("encode");
    let decoded: CompactReport = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(
        encoded,
        serde_json::to_string(&decoded).expect("re-encode"),
        "`uses` did not survive the wire round trip",
    );
}

#[test]
fn full_report_roundtrips_byte_for_byte() {
    use super::super::file_analysis::FileAnalysis;
    use super::super::traits_findings::Finding;
    use super::super::{Criticality, FindingKind};

    let mut fa = FileAnalysis::new(
        0,
        "pkg.zip!!lib/mod.py".to_string(),
        "python".to_string(),
        "a".repeat(64),
        4096,
    );
    let mut finding = Finding::new(
        "objectives/execution/shell",
        FindingKind::Capability,
        "spawns a shell",
        0.9,
    );
    finding.crit = Criticality::Suspicious;
    fa.findings.push(finding);
    fa.depth = 1;
    fa.parent_id = Some(0);

    // A suppression rides the same round trip: it is the only record of
    // what the analysis withheld, so a lossy encode would silently erase it.
    fa.suppressions.push(crate::types::Suppression {
        id: "objectives/execution/shell".into(),
        crit: Criticality::Suspicious,
        kind: crate::types::SuppressionKind::Unless,
        by: vec![crate::types::SuppressionLeg {
            id: "metadata/package/testing/harness/runtime::is-test".into(),
            spans: vec![[0, 57]],
        }],
    });

    let report = compact_from_files(&[fa], Facts::Full);
    let encoded = serde_json::to_string(&report).expect("encode");
    let decoded: CompactReport = serde_json::from_str(&encoded).expect("decode");
    assert_eq!(
        encoded,
        serde_json::to_string(&decoded).expect("re-encode"),
        "a full compact report did not survive the wire round trip"
    );
    assert_eq!(decoded.files.len(), 1);
    assert_eq!(decoded.files[0].findings.len(), 1);
    assert_eq!(
        decoded.files[0].suppressions, report.files[0].suppressions,
        "suppressions did not survive the wire round trip"
    );
    assert_eq!(decoded.version, SCHEMA_VERSION);
}

/// Every `CompactFacts` field is omitted when empty, so the decoder must
/// default each one rather than fail — and an all-empty block must survive
/// as all-empty.
#[test]
fn facts_roundtrips_sparse_and_populated() {
    let empty = CompactFacts {
        metrics: None,
        imports: Vec::new(),
        exports: Vec::new(),
        functions: Vec::new(),
        sections: Vec::new(),
        targets: Vec::new(),
        members: Vec::new(),
    };
    assert_eq!(roundtrip(&empty), serde_json::json!({}));

    let populated = CompactFacts {
        metrics: Some(RoundedMetrics(
            serde_json::json!({"binary": {"entropy": 6.5}}),
        )),
        imports: vec![CompactImport {
            library: "libc".into(),
            name: "execve".into(),
            ordinal: None,
        }],
        exports: Vec::new(),
        functions: vec![CompactFunction {
            name: "f".into(),
            offset: Some(1),
            kind: None,
        }],
        sections: Vec::new(),
        targets: vec!["os.system".into()],
        members: vec!["a.b".into()],
    };
    let wire = roundtrip(&populated);
    // Field *names* are part of the contract the featurizer reads.
    let obj = wire.as_object().unwrap();
    assert!(obj.contains_key("metrics") && obj.contains_key("imp"));
    assert!(obj.contains_key("funcs") && obj.contains_key("tgt") && obj.contains_key("mbr"));
    assert!(!obj.contains_key("exp"), "empty fields stay omitted");
}
