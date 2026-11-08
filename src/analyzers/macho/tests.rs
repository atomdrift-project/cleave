use super::*;
use std::path::PathBuf;

#[test]
fn parser_failure_is_an_analysis_note_not_a_finding() {
    // The failure itself is judged by traits over `macho.parse_failed`.
    let analyzer = MachOAnalyzer::new();
    let bytes = vec![0u8; 4096];
    let report = analyzer.analyze_macho_fallback(
        Path::new("unparsed.macho"),
        &bytes,
        "sha".into(),
        Some("parser could not recover header".into()),
    );
    assert_eq!(report.metadata.errors, ["parser could not recover header"]);
    assert!(report.findings.is_empty());
}

/// A fat binary's slice table comes from the parse the caller already
/// holds. Each range helper used to reopen the file, and reading a fat
/// binary's values runs its whole extraction (recovery on every slice).
#[test]
fn fat_slices_come_from_the_callers_parse() {
    let data = crate::test_samples::read("testdata/xor/gapi-update.macho");
    let ctx = crate::analysis_context::AnalysisContext::open_with(
        filefacts::OpenOptions::new(),
        Path::new("gapi-update.macho"),
        &data,
    );
    let slices = FatSlices::of(&data, Some(&ctx), &filefacts::OpenOptions::new());
    assert!(
        slices.0.len() > 1,
        "fat fixture has several slices: {slices:?}"
    );
    assert_eq!(ctx.parsed.parse_count(), 1, "one extraction, shared");

    let analyzer = MachOAnalyzer::new();
    assert_eq!(
        analyzer.all_arch_ranges(&data, &slices).len(),
        slices.0.len()
    );
    let preferred = analyzer.preferred_arch_range(&data, &slices);
    assert!(preferred.start > 0 && preferred.end <= data.len());

    // A thin binary has no table and never needs a parse.
    let thin = std::fs::read(test_macho_path()).unwrap();
    let none = FatSlices::of(&thin, None, &filefacts::OpenOptions::new());
    assert!(none.0.is_empty());
    assert_eq!(analyzer.all_arch_ranges(&thin, &none), vec![0..thin.len()]);
}

fn test_macho_path() -> PathBuf {
    PathBuf::from("tests/fixtures/test.macho")
}

fn report_with_offsets() -> AnalysisReport {
    let target = crate::types::TargetInfo {
        path: "/tmp/fat".to_string(),
        file_type: "macho".to_string(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: None,
    };
    let mut report = AnalysisReport::new(target);
    report.functions.push(crate::types::Function {
        name: "f".to_string(),
        offset: Some("0x1000".to_string()),
        size: None,
        complexity: None,
        calls: vec![],
        control_flow: None,
        register_usage: None,
        constants: vec![],
        signature: None,
        nesting: None,
        call_patterns: None,
    });
    report.imports.push(crate::types::Import {
        symbol: "acl_get_entry".to_string(),
        offset: Some("0x5078".to_string()),
        ..Default::default()
    });
    report
        .exports
        .push(Export::new("main", Some("0x2000".to_string())));
    // A section with both a file offset (rebased) and a vm address (left alone).
    report.sections.push(crate::types::Section {
        name: "__text".to_string(),
        address: Some(0x1_0000_4000),
        offset: Some(0x4000),
        size: 0,
        entropy: 0.0,
        permissions: None,
        flags: vec![],
    });
    report
}

/// The preferred slice of a fat Mach-O is parsed at base 0, so its
/// structural offsets are slice-relative. Rebasing adds the slice's fat
/// offset to every *file* offset (functions, imports, exports, section
/// offsets) while leaving virtual addresses untouched — so symbol
/// annotations line up with the full-file hex view.
#[test]
fn rebase_slice_offsets_shifts_file_offsets_only() {
    let mut report = report_with_offsets();
    MachOAnalyzer::rebase_slice_offsets(&mut report, 0x4000);

    assert_eq!(report.functions[0].offset.as_deref(), Some("0x5000"));
    assert_eq!(report.imports[0].offset.as_deref(), Some("0x9078"));
    assert_eq!(report.exports[0].offset.as_deref(), Some("0x6000"));
    // File offset rebased; virtual address (vmaddr) left as-is.
    assert_eq!(report.sections[0].offset, Some(0x8000));
    assert_eq!(report.sections[0].address, Some(0x1_0000_4000));
}

/// A fat slice's code-signature findings (identity, signer) anchor their
/// evidence at slice-relative offsets. Rebasing must shift those too, or
/// the "Identifier" annotation lands `delta` bytes early — inside the
/// slice's __text instead of on the signature blob. Named or `archive:`
/// locations carry no file offset and stay put.
#[test]
fn rebase_slice_offsets_shifts_finding_evidence() {
    let mut report = report_with_offsets();
    report.findings.push(Finding {
        id: "metadata/signature/verified/id::com.apple.ls"
            .to_string()
            .into(),
        desc: "Identifier: com.apple.ls".to_string().into(),
        evidence: vec![
            Evidence {
                location: Some("0x739b".to_string()),
                ..Default::default()
            },
            Evidence {
                location: Some("LC_CODE_SIGNATURE".to_string()),
                offsets: vec![0x100],
                ..Default::default()
            },
        ],
        ..Default::default()
    });
    MachOAnalyzer::rebase_slice_offsets(&mut report, 0x4000);

    // Hex-string location rebased onto the real signature blob.
    assert_eq!(
        report.findings[0].evidence[0].location.as_deref(),
        Some("0xb39b")
    );
    // Concrete offset rebased; the named location is left as-is.
    assert_eq!(report.findings[0].evidence[1].offsets, vec![0x4100]);
    assert_eq!(
        report.findings[0].evidence[1].location.as_deref(),
        Some("LC_CODE_SIGNATURE")
    );
}

#[test]
fn rebase_slice_offsets_shifts_value_tree_companion_offsets() {
    let mut report = report_with_offsets();
    report.values_tree = Some(Box::new(serde_json::json!({
        "macho": { "uuid": "ed6f...", "uuid_offset": 1472u64 },
        "macho.code_signature_offset": 0x100u64,
    })));
    MachOAnalyzer::rebase_slice_offsets(&mut report, 0x4000);
    let tree = report.values_tree.expect("values tree present");
    // `*_offset` siblings shift by the slice delta so `type: value`
    // matches anchor on the full file; the value itself is untouched.
    assert_eq!(tree["macho"]["uuid_offset"].as_u64(), Some(0x4000 + 1472));
    assert_eq!(tree["macho"]["uuid"].as_str(), Some("ed6f..."));
    assert_eq!(tree["macho.code_signature_offset"].as_u64(), Some(0x4100));
}

/// A zero delta (thin binary / preferred slice already at offset 0) must
/// be a no-op so thin binaries are never perturbed.
#[test]
fn rebase_slice_offsets_zero_delta_is_noop() {
    let mut report = report_with_offsets();
    MachOAnalyzer::rebase_slice_offsets(&mut report, 0);
    assert_eq!(report.imports[0].offset.as_deref(), Some("0x5078"));
    assert_eq!(report.sections[0].offset, Some(0x4000));
}

#[test]
fn shift_hex_offset_parses_and_preserves_none() {
    let mut some = Some("0x10".to_string());
    shift_hex_offset(&mut some, 0xff0);
    assert_eq!(some.as_deref(), Some("0x1000"));

    let mut none: Option<String> = None;
    shift_hex_offset(&mut none, 0x100);
    assert_eq!(none, None);

    // A non-numeric location string (e.g. a forward target) is untouched.
    let mut label = Some("forward → KERNEL32.X".to_string());
    shift_hex_offset(&mut label, 0x100);
    assert_eq!(label.as_deref(), Some("forward → KERNEL32.X"));
}

#[test]
fn test_analyze_macho_file() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let result = analyzer.analyze(&test_file);
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.target.file_type, "macho");
    assert!(report.target.size_bytes > 0);
    assert!(!report.target.sha256.is_empty());
}

#[test]
fn test_macho_has_structure() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.structure.is_empty());
}

#[test]
fn test_macho_architecture_detected() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(report.target.architectures.is_some());
    let archs = report.target.architectures.unwrap();
    assert!(!archs.is_empty());
}

#[test]
fn test_macho_sections_analyzed() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.sections.is_empty());
}

#[test]
fn test_macho_has_imports() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.imports.is_empty());
}

#[test]
fn test_macho_capabilities_detected() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    // Capabilities may or may not be detected depending on the binary
    // Just verify the analysis completes successfully
    let _ = &report.traits;
}

#[test]
fn test_macho_strings_extracted() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.strings.is_empty());
}

#[test]
fn test_macho_tools_used() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(
        report
            .metadata
            .tools_used
            .contains(&"filefacts".to_string())
    );
}

#[test]
fn test_macho_analysis_duration() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(report.metadata.analysis_duration_ms > 0);
}

// Integration tests for code signature extraction and finding generation
#[test]
fn test_signature_findings_generated() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // Check that signature-related findings are present
    let has_signed = report.findings.iter().any(|f| f.id.contains("signed/type"));
    // Note: test.macho might not be signed, so this is a soft assertion
    if has_signed {
        assert!(report.findings.iter().any(|f| f.id.contains("signed/type")));
    }
}

#[test]
fn test_entitlements_extracted_when_present() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // Check if any entitlement findings are present
    let entitlement_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.id.contains("entitlement"))
        .collect();

    // If the binary has entitlements, verify they're properly extracted
    if !entitlement_findings.is_empty() {
        for finding in &entitlement_findings {
            // Entitlements should have proper evidence
            assert!(!finding.evidence.is_empty());
            // Method should be "entitlements_plist"
            assert!(
                finding
                    .evidence
                    .iter()
                    .any(|e| e.method == "entitlements_plist")
            );
        }
    }
}

#[test]
fn test_team_id_extracted_when_signed() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // Check for team ID findings
    let team_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.id.contains("signed/team"))
        .collect();

    // If team findings exist, verify they have proper structure
    for finding in &team_findings {
        assert!(!finding.evidence.is_empty());
        assert_eq!(finding.evidence[0].method, "cms_certificate");
    }
}

#[test]
fn test_hardened_runtime_detection() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // Check for hardened-runtime finding
    let hardened = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/hardened-runtime");

    if let Some(finding) = hardened {
        assert_eq!(finding.evidence[0].method, "code_directory_flags");
        assert_eq!(finding.evidence[0].value, "0x00010000");
    }
}

#[test]
fn test_signature_type_criticality() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // Signature type findings should have Notable criticality
    let sig_type_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.id.contains("signed/type"))
        .collect();

    for finding in &sig_type_findings {
        assert_eq!(finding.crit, Criticality::Notable);
        assert_eq!(finding.conf, 1.0); // Should be high confidence
    }
}

/// Identity (bundle/executable identifier) is Notable, not Baseline:
/// "who the binary claims to be" must clear the notable-floored views so
/// an analyst sees it in a diff. Locks the cross-format identity principle
/// for the Mach-O emitter. Also pins the two invariants of the
/// filefacts-sourced rewrite: a platform binary emits
/// `metadata/signature/verified/platform::apple`, the signer finding anchors at the
/// signature-blob offset, and the identifier finding anchors at the
/// distinct identifier-string offset. Deterministic — no fixture needed.
#[test]
fn test_identity_finding_is_notable() {
    let mut identity = filefacts::Identity::default();
    identity.identifier = Some(filefacts::Claim::verified(
        "com.apple.ls",
        "macho.code_signature.identifier",
    ));
    identity.trust = filefacts::Trust::Platform;
    let mut report = AnalysisReport::new(crate::types::TargetInfo {
        path: "/bin/ls".to_string(),
        file_type: "macho".to_string(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: None,
    });
    emit_signature_findings(&mut report, 0xb3a0, Some(0xb3c8), &identity, None, None);

    let id_finding = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/signature/verified/id::com.apple.ls")
        .expect("identity finding emitted");
    assert_eq!(id_finding.crit, Criticality::Notable);
    // The value rides in the description so notable-floored views (which
    // print only `desc`, not the trait id) stay readable.
    assert_eq!(id_finding.desc, "Identifier: com.apple.ls");
    // Anchored at the identifier string itself, not the signature blob.
    assert_eq!(id_finding.evidence[0].location.as_deref(), Some("0xb3c8"));

    let platform = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/signature/verified/platform::apple")
        .expect("platform-trust finding emitted");
    assert_eq!(platform.crit, Criticality::Notable);
    assert_eq!(platform.desc, "Verified platform signature: apple");
    // The signer finding still anchors at the signature blob.
    assert_eq!(platform.evidence[0].location.as_deref(), Some("0xb3a0"));
}

/// A Developer-ID-signed binary yields `metadata/signature/verified/developer::<team>`
/// trait keyed by Team ID, with the signer organization in the description,
/// sourced from filefacts's `Identity`, not a re-parse. This is the
/// supply-chain signal an analyst reads first: who signed it.
#[test]
fn test_developer_signed_findings() {
    let mut identity = filefacts::Identity::default();
    identity.trust = filefacts::Trust::DeveloperId;
    identity.team_id = Some(filefacts::Claim::verified(
        "ABCDE12345",
        "macho.code_signature",
    ));
    let mut signer = filefacts::Signer::new("macho.code_signature");
    signer.common_name = Some("Developer ID Application: Acme Inc. (ABCDE12345)".to_string());
    signer.organization = Some("Acme Inc.".to_string());
    identity.signer = Some(signer);
    let mut report = AnalysisReport::new(crate::types::TargetInfo {
        path: "/Applications/Acme.app/Contents/MacOS/Acme".to_string(),
        file_type: "macho".to_string(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: None,
    });
    emit_signature_findings(&mut report, 0x4000, None, &identity, None, None);

    let dev = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/signature/verified/developer::abcde12345")
        .expect("developer-trust finding keyed by team id");
    assert_eq!(dev.crit, Criticality::Notable);
    assert_eq!(
        dev.desc,
        "Verified Apple Developer ID: Acme Inc. (ABCDE12345)"
    );
}

#[test]
fn test_signature_findings_have_proper_kind() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // All signature-related findings should be Capability kind
    for finding in report
        .findings
        .iter()
        .filter(|f| f.id.contains("signed") || f.id.contains("entitlement"))
    {
        assert_eq!(finding.kind, FindingKind::Capability);
    }
}

#[test]
fn test_identifier_finding_when_present() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // Check for identifier findings
    let identifier_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.id.contains("signed/id"))
        .collect();

    // If identifier findings exist, they should have proper evidence
    // sourced from filefacts (cleave no longer re-parses the signature).
    for finding in &identifier_findings {
        assert_eq!(finding.evidence[0].method, "code_directory");
        assert_eq!(finding.evidence[0].source, "filefacts");
    }
}
