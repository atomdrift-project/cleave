#[test]
fn evidence_json_roundtrip_sanitizes_nul_but_preserves_source_span() {
    use super::{Evidence, Finding, finding_spans};

    let value = "parseInt\0\u{1}\u{16}(Ljava/lang/String;I)I";
    let evidence = Evidence {
        method: "hex".into(),
        value: value.into(),
        offsets: vec![4243],
        ..Default::default()
    };

    let json = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!json.contains('\0'));
    assert!(json.contains("parseInt\\u0001\\u0016(Ljava/lang/String;I)I"));
    assert!(json.contains("\"match_len\":33"));

    let restored: Evidence = serde_json::from_str(&json).expect("serialized evidence deserializes");
    assert_eq!(restored.value, "parseInt\u{1}\u{16}(Ljava/lang/String;I)I");
    assert_eq!(restored.match_len, Some(33));
    let finding = Finding {
        evidence: vec![restored],
        ..Default::default()
    };
    assert_eq!(finding_spans(&finding), [[4243, 33]]);
}

#[test]
fn evidence_json_roundtrip_preserves_explicit_span_after_sanitization() {
    use super::{Evidence, Finding, finding_spans};

    let evidence = Evidence {
        method: "decoded".into(),
        value: "source\0value".into(),
        offsets: vec![91],
        match_len: Some(7),
        ..Default::default()
    };

    let json = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(json.contains("\"match_len\":7"));
    let restored: Evidence = serde_json::from_str(&json).expect("evidence deserializes");
    assert_eq!(restored.match_len, Some(7));
    assert_eq!(
        finding_spans(&Finding {
            evidence: vec![restored],
            ..Default::default()
        }),
        [[91, 7]]
    );
}

#[test]
fn evidence_json_roundtrip_preserves_span_before_value_truncation() {
    use super::{Evidence, Finding, MAX_EVIDENCE_VALUE_SIZE, finding_spans};

    let evidence = Evidence {
        method: "raw".into(),
        value: "x".repeat(MAX_EVIDENCE_VALUE_SIZE + 100),
        offsets: vec![123],
        ..Default::default()
    };

    let json = serde_json::to_string(&evidence).expect("evidence serializes");
    let restored: Evidence = serde_json::from_str(&json).expect("evidence deserializes");
    assert!(restored.value.len() <= MAX_EVIDENCE_VALUE_SIZE);
    assert_eq!(
        restored.match_len,
        Some((MAX_EVIDENCE_VALUE_SIZE + 100) as u64)
    );
    assert_eq!(
        finding_spans(&Finding {
            evidence: vec![restored],
            ..Default::default()
        }),
        [[123, (MAX_EVIDENCE_VALUE_SIZE + 100) as u64]]
    );
}

#[test]
fn legacy_evidence_json_without_match_len_keeps_value_length_fallback() {
    use super::{Evidence, Finding, finding_spans};

    let restored: Evidence =
        serde_json::from_str(r#"{"method":"raw","value":"legacy","offsets":[17]}"#)
            .expect("legacy evidence deserializes");
    assert_eq!(restored.match_len, None);
    assert_eq!(
        finding_spans(&Finding {
            evidence: vec![restored],
            ..Default::default()
        }),
        [[17, 6]]
    );
}

#[test]
fn finding_spans_prefers_widest_span_when_offsets_tie() {
    use super::{Evidence, Finding, finding_spans};

    let finding_with = |lengths: [u64; 2]| Finding {
        evidence: lengths
            .into_iter()
            .map(|length| Evidence {
                method: "hex".into(),
                value: "matched bytes".into(),
                offsets: vec![4243],
                match_len: Some(length),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };

    assert_eq!(finding_spans(&finding_with([32, 33])), [[4243, 33]]);
    assert_eq!(finding_spans(&finding_with([33, 32])), [[4243, 33]]);
}

#[test]
fn span_dedup_keeps_widest_nested_range_and_sorts_offsets() {
    use super::sort_dedup_spans_by_offset;

    let mut spans = vec![[9, 0], [4, 32], [2, 1], [4, 33], [9, 10], [4, 0], [2, 0]];
    sort_dedup_spans_by_offset(&mut spans);
    assert_eq!(spans, [[2, 1], [4, 33], [9, 10]]);

    let mut reverse = vec![[2, 0], [4, 0], [9, 10], [4, 33], [2, 1], [4, 32], [9, 0]];
    sort_dedup_spans_by_offset(&mut reverse);
    assert_eq!(reverse, spans);
}

#[test]
fn finding_spans_merges_precomputed_and_live_evidence() {
    use super::{Evidence, Finding, finding_spans};

    let finding = Finding {
        evidence: vec![Evidence {
            method: "hex".into(),
            value: "matched bytes".into(),
            offsets: vec![9],
            match_len: Some(32),
            ..Default::default()
        }],
        precomputed_spans: Some(vec![[9, 33], [4, 2]]),
        ..Default::default()
    };

    assert_eq!(finding_spans(&finding), [[4, 2], [9, 33]]);
}

#[test]
fn duplicate_evidence_merge_keeps_widest_effective_source_length() {
    use super::{Evidence, deduplicate_evidence};

    let evidence = |length| Evidence {
        method: "raw".into(),
        source: "same-source".into(),
        value: "same evidence".into(),
        offsets: vec![4243],
        match_len: length,
        ..Default::default()
    };
    for pair in [[Some(32), Some(33)], [Some(33), Some(32)]] {
        let merged = deduplicate_evidence(pair.into_iter().map(evidence).collect());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].match_len, Some(33));
        assert_eq!(super::evidence_spans(&merged), [[4243, 33]]);
    }

    // `None` means value length. An explicit shorter source range must not
    // shrink the ordinary value-length span when duplicate rows merge.
    let value_len = "same evidence".len() as u64;
    for pair in [[None, Some(5)], [Some(5), None]] {
        let merged = deduplicate_evidence(pair.into_iter().map(evidence).collect());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].match_len, None);
        assert_eq!(super::evidence_spans(&merged), [[4243, value_len]]);
    }
}

/// Dependent-trait rounds and archive members record the same suppression
/// more than once, from parallel workers in whatever order they finish.
/// The drained result must not depend on that order.
#[test]
fn suppression_drain_is_independent_of_record_order() {
    use super::{Criticality, Suppression, SuppressionKind, SuppressionLeg, SuppressionSink};
    let record = |leg: &str, span: u64| Suppression {
        id: "a/b::withheld".into(),
        crit: Criticality::Notable,
        kind: SuppressionKind::Unless,
        by: vec![SuppressionLeg {
            id: leg.into(),
            spans: vec![[span, 4]],
        }],
    };
    let drain = |records: Vec<Suppression>| {
        let sink = SuppressionSink::default();
        for r in records {
            sink.push(r);
        }
        sink.drain()
    };
    let forward = drain(vec![
        record("x/y::one", 8),
        record("x/y::two", 4),
        record("x/y::one", 2),
    ]);
    let backward = drain(vec![
        record("x/y::one", 2),
        record("x/y::two", 4),
        record("x/y::one", 8),
    ]);
    assert_eq!(forward, backward);
    assert_eq!(forward.len(), 1);
    let legs: Vec<&str> = forward[0].by.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(legs, ["x/y::one", "x/y::two"]);
    assert_eq!(forward[0].by[0].spans, [[2, 4], [8, 4]]);
}

/// Fold-time bounding must be idempotent with serialization: the bounded
/// form re-bounds to itself, so a member bounded at fold serializes
/// byte-identically to one bounded only on the wire.
#[test]
fn bound_evidence_value_is_idempotent() {
    let long = "x".repeat(MAX_EVIDENCE_VALUE_SIZE * 2);
    let bounded = bound_evidence_value(&long).expect("over-cap value is bounded");
    assert!(bounded.len() <= MAX_EVIDENCE_VALUE_SIZE);
    assert!(bounded.ends_with("...[truncated]"));
    assert_eq!(
        bound_evidence_value(&bounded),
        None,
        "already-bounded value passes through untouched"
    );

    assert_eq!(bound_evidence_value("short"), None);
    assert_eq!(
        bound_evidence_value("nul\0led").as_deref(),
        Some("nulled"),
        "sanitization applies below the cap too"
    );
}
use super::*;

// ==================== TraitKind Tests ====================

#[test]
fn test_trait_kind_equality() {
    assert_eq!(TraitKind::String, TraitKind::String);
    assert_ne!(TraitKind::String, TraitKind::Path);
}

#[test]
fn test_trait_kind_all_variants() {
    // Ensure all variants are distinct
    let variants = vec![
        TraitKind::String,
        TraitKind::Path,
        TraitKind::EnvVar,
        TraitKind::Import,
        TraitKind::Export,
        TraitKind::Ip,
        TraitKind::Url,
        TraitKind::Domain,
        TraitKind::Email,
        TraitKind::Base64,
        TraitKind::Hash,
        TraitKind::Registry,
        TraitKind::Function,
    ];
    for (i, v1) in variants.iter().enumerate() {
        for (j, v2) in variants.iter().enumerate() {
            if i == j {
                assert_eq!(v1, v2);
            } else {
                assert_ne!(v1, v2);
            }
        }
    }
}

// ==================== reanchor_offset Tests ====================

/// A content match that stored its offset only in `location` (the common
/// case for string/text/string_literal matchers) must keep that offset when
/// the location is later relabeled — otherwise `byte_offset` returns `None`
/// and the context pass reports it as anchor-less.
#[test]
fn reanchor_lifts_location_only_offset_into_offsets() {
    let mut ev = Evidence {
        method: "string_literal".to_string(),
        location: Some("0x1a".to_string()),
        ..Default::default()
    };
    ev.reanchor_offset(0x100);
    assert_eq!(ev.offsets, vec![0x11a]);
    // Relabeling the location no longer strands the offset.
    ev.location = Some("embedded@0x100:0x1a".to_string());
    assert_eq!(ev.byte_offset(), Some(0x11a));
}

/// With a zero shift (evidence rendered against its own sub-buffer) the
/// location offset is preserved verbatim.
#[test]
fn reanchor_zero_shift_preserves_local_offset() {
    let mut ev = Evidence {
        method: "text".to_string(),
        location: Some("0x40".to_string()),
        ..Default::default()
    };
    ev.reanchor_offset(0);
    assert_eq!(ev.offsets, vec![0x40]);
}

/// Existing concrete offsets are shifted (not duplicated) into the parent's
/// byte space.
#[test]
fn reanchor_shifts_existing_offsets() {
    let mut ev = Evidence {
        method: "raw".to_string(),
        offsets: vec![0x10, 0x20],
        location: Some("0x10".to_string()),
        ..Default::default()
    };
    ev.reanchor_offset(0x1000);
    assert_eq!(ev.offsets, vec![0x1010, 0x1020]);
}

/// Evidence with neither offsets nor a parseable location gains nothing —
/// genuinely position-less facts stay position-less.
#[test]
fn reanchor_noop_without_any_offset() {
    let mut ev = Evidence {
        method: "string".to_string(),
        location: Some("import".to_string()),
        ..Default::default()
    };
    ev.reanchor_offset(0x100);
    assert!(ev.offsets.is_empty());
    assert_eq!(ev.byte_offset(), None);
}

// ==================== FindingKind Tests ====================

#[test]
fn test_finding_kind_default() {
    assert_eq!(FindingKind::default(), FindingKind::Capability);
}

#[test]
fn test_finding_kind_equality() {
    assert_eq!(FindingKind::Capability, FindingKind::Capability);
    assert_ne!(FindingKind::Capability, FindingKind::Structural);
}

// ==================== Finding Tests ====================

#[test]
fn test_finding_new() {
    let f = Finding::new(
        "test/cap".to_string(),
        FindingKind::Capability,
        "Test capability".to_string(),
        0.9,
    );

    assert_eq!(f.id, "test/cap");
    assert_eq!(f.kind, FindingKind::Capability);
    assert_eq!(f.desc, "Test capability");
    assert!((f.conf - 0.9).abs() < f32::EPSILON);
    assert_eq!(f.crit, Criticality::Baseline);
    assert!(f.mbc.is_none());
    assert!(f.attack.is_none());
    assert!(f.trait_refs.is_empty());
    assert!(f.evidence.is_empty());
}

#[test]
fn test_finding_capability() {
    let f = Finding::capability(
        "net/socket".to_string(),
        "Socket operations".to_string(),
        0.8,
    );

    assert_eq!(f.id, "net/socket");
    assert_eq!(f.kind, FindingKind::Capability);
}

#[test]
fn test_finding_structural() {
    let f = Finding::structural(
        "obfuscation/base64".to_string(),
        "Base64 obfuscation".to_string(),
        0.7,
    );

    assert_eq!(f.kind, FindingKind::Structural);
}

#[test]
fn test_finding_indicator() {
    let f = Finding::indicator(
        "command-and-control/beacon".to_string(),
        "C2 beacon pattern".to_string(),
        0.95,
    );

    assert_eq!(f.kind, FindingKind::Indicator);
}

#[test]
fn test_finding_with_criticality() {
    let f = Finding::capability("test".to_string(), "desc".to_string(), 0.9)
        .with_criticality(Criticality::Hostile);

    assert_eq!(f.crit, Criticality::Hostile);
}

#[test]
fn test_finding_with_mbc() {
    let f = Finding::capability("test".to_string(), "desc".to_string(), 0.9).with_mbc("B0015.001");

    assert_eq!(f.mbc, Some(crate::types::Istr::from("B0015.001")));
}

#[test]
fn test_finding_with_attack() {
    let f =
        Finding::capability("test".to_string(), "desc".to_string(), 0.9).with_attack("T1059.001");

    assert_eq!(f.attack, Some(crate::types::Istr::from("T1059.001")));
}

#[test]
fn test_finding_with_evidence() {
    let evidence = vec![Evidence {
        method: "symbol".to_string(),
        source: "goblin".to_string(),
        value: "connect".to_string(),
        location: Some("0x1000".to_string()),
        ..Default::default()
    }];

    let f =
        Finding::capability("test".to_string(), "desc".to_string(), 0.9).with_evidence(evidence);

    assert_eq!(f.evidence.len(), 1);
    assert_eq!(f.evidence[0].value, "connect");
}

#[test]
fn test_finding_builder_chain() {
    let f = Finding::capability("net/http".to_string(), "HTTP client".to_string(), 0.95)
        .with_criticality(Criticality::Suspicious)
        .with_mbc("C0002")
        .with_attack("T1071.001");

    assert_eq!(f.id, "net/http");
    assert_eq!(f.crit, Criticality::Suspicious);
    assert_eq!(f.mbc, Some(crate::types::Istr::from("C0002")));
    assert_eq!(f.attack, Some(crate::types::Istr::from("T1071.001")));
}

// ==================== truncate_str Tests ====================

#[test]
fn test_truncate_str_short() {
    let s = "hello";
    assert_eq!(truncate_str(s, 100), "hello");
}

#[test]
fn test_truncate_str_exact() {
    let s = "hello";
    assert_eq!(truncate_str(s, 5), "hello");
}

#[test]
fn test_truncate_str_cut() {
    let s = "hello world";
    assert_eq!(truncate_str(s, 5), "hello");
}

#[test]
fn test_truncate_str_utf8_boundary() {
    // "é" is 2 bytes in UTF-8
    let s = "café";
    // Truncating at byte 3 would split the é, so it should back up to byte 3 (caf)
    let result = truncate_str(s, 4);
    assert_eq!(result, "caf");
}

#[test]
fn test_truncate_str_multibyte() {
    // "日" is 3 bytes in UTF-8
    let s = "日本語"; // 9 bytes total
    // Truncating at 5 bytes should give us just "日" (3 bytes)
    let result = truncate_str(s, 5);
    assert_eq!(result, "日");
}

#[test]
fn test_truncate_str_zero() {
    let s = "hello";
    assert_eq!(truncate_str(s, 0), "");
}

// ==================== Evidence Tests ====================

#[test]
fn test_evidence_creation() {
    let e = Evidence {
        method: "yara".to_string(),
        source: "yara-x".to_string(),
        value: "suspicious_pattern".to_string(),
        location: Some("0x1234".to_string()),
        ..Default::default()
    };

    assert_eq!(e.method, "yara");
    assert_eq!(e.value, "suspicious_pattern");
    assert_eq!(e.location, Some("0x1234".to_string()));
}

#[test]
fn test_evidence_no_location() {
    let e = Evidence {
        method: "import".to_string(),
        source: "goblin".to_string(),
        value: "CreateRemoteThread".to_string(),
        location: None,
        ..Default::default()
    };

    assert!(e.location.is_none());
}

// ==================== StructuralFeature Tests ====================

#[test]
fn test_structural_feature_creation() {
    let sf = StructuralFeature {
        id: "binary/format/pe".to_string(),
        desc: "PE executable format".to_string(),
        evidence: vec![Evidence {
            method: "magic".to_string(),
            source: "goblin".to_string(),
            value: "MZ".to_string(),
            location: Some("0x0".to_string()),
            ..Default::default()
        }],
    };

    assert_eq!(sf.id, "binary/format/pe");
    assert_eq!(sf.evidence.len(), 1);
}
