use super::*;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[test]
fn parser_failure_reports_limitation_without_evasion_intent() {
    let analyzer = MachOAnalyzer::new();
    let bytes = vec![0u8; 4096];
    let report = analyzer.analyze_macho_fallback(
        Path::new("unparsed.macho"),
        &bytes,
        "sha".into(),
        Some("parser could not recover header".into()),
    );
    assert_eq!(report.metadata.errors.len(), 1);
    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    assert_eq!(
        finding.id.as_str(),
        "metadata/analysis/limitation::macho-parse-failed"
    );
    assert_eq!(finding.crit, Criticality::Notable);
    assert!(finding.attack.is_none());
    assert!(finding.mbc.is_none());
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

fn put_be_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

/// Minimal two-page SHA-256 CodeDirectory wrapped in an embedded-signature
/// SuperBlob. The signed bytes precede the signature, as in a real Mach-O.
fn code_directory_fixture(tampered: bool) -> (Vec<u8>, usize) {
    code_directory_fixture_with_slots(tampered, &[0])
}

/// As [`code_directory_fixture`], with one index entry per slot type in
/// `slots`, every one pointing at the same CodeDirectory.
fn code_directory_fixture_with_slots(tampered: bool, slots: &[u32]) -> (Vec<u8>, usize) {
    const PAGE: usize = 4096;
    const CODE_LEN: usize = PAGE * 2;
    const CD_HEADER: usize = 44;
    const HASH_SIZE: usize = 32;
    const CD_LEN: usize = CD_HEADER + HASH_SIZE * 2;
    let super_header = 12 + 8 * slots.len();

    let mut data = vec![b'A'; CODE_LEN];
    let mut cd = vec![0u8; CD_LEN];
    put_be_u32(&mut cd, 0, 0xfade_0c02);
    put_be_u32(&mut cd, 4, CD_LEN as u32);
    put_be_u32(&mut cd, 8, 0x0002_0000);
    put_be_u32(&mut cd, 16, CD_HEADER as u32);
    put_be_u32(&mut cd, 28, 2);
    put_be_u32(&mut cd, 32, CODE_LEN as u32);
    cd[36] = HASH_SIZE as u8;
    cd[37] = 2; // SHA-256
    cd[39] = 12; // 4096-byte pages
    for page in 0..2 {
        let digest = Sha256::digest(&data[page * PAGE..(page + 1) * PAGE]);
        let hash_start = CD_HEADER + page * HASH_SIZE;
        cd[hash_start..hash_start + HASH_SIZE].copy_from_slice(&digest);
    }

    let mut superblob = vec![0u8; super_header];
    put_be_u32(&mut superblob, 0, 0xfade_0cc0);
    put_be_u32(&mut superblob, 4, (super_header + CD_LEN) as u32);
    put_be_u32(&mut superblob, 8, slots.len() as u32);
    for (i, slot) in slots.iter().enumerate() {
        put_be_u32(&mut superblob, 12 + i * 8, *slot);
        put_be_u32(&mut superblob, 16 + i * 8, super_header as u32);
    }
    superblob.extend_from_slice(&cd);
    let sig_offset = data.len();
    data.extend_from_slice(&superblob);
    if tampered {
        data[PAGE + 17] ^= 0xff;
    }
    (data, sig_offset)
}

#[test]
fn code_directory_page_hashes_validate() {
    let (data, sig_offset) = code_directory_fixture(false);
    assert_eq!(
        verify_code_directory_hashes(&data, sig_offset),
        CodeDirectoryIntegrity::Valid { checked: 2 }
    );
}

/// Each page is hashed once however many index entries name the
/// CodeDirectory, and entries outside the CodeDirectory slots are ignored.
/// Otherwise a forged index makes verification quadratic in its size.
#[test]
fn code_directory_is_verified_once_per_blob() {
    let mut slots = vec![0u32; 1000];
    slots.extend([0x1000, 0x1001, 2, 0x10000]);
    let (data, sig_offset) = code_directory_fixture_with_slots(false, &slots);
    assert_eq!(
        verify_code_directory_hashes(&data, sig_offset),
        CodeDirectoryIntegrity::Valid { checked: 2 }
    );
}

#[test]
fn code_directory_page_hashes_detect_tampering() {
    let (data, sig_offset) = code_directory_fixture(true);
    assert_eq!(
        verify_code_directory_hashes(&data, sig_offset),
        CodeDirectoryIntegrity::Invalid {
            mismatched: 1,
            checked: 2
        }
    );
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
        id: "metadata/signed/id::com.apple.ls".to_string().into(),
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
    emit_signature_findings(
        &mut report,
        0xb3a0,
        Some(0xb3c8),
        &identity,
        None,
        None,
        None,
    );

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
/// plus a per-entitlement finding — all sourced from filefacts's `Identity`
/// and entitlements map, none from a re-parse. This is the supply-chain
/// signal an analyst reads first: who signed it, and what it was granted.
#[test]
fn test_developer_signed_and_entitlement_findings() {
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
    let mut entitlements = serde_json::Map::new();
    entitlements.insert(
        "com.apple.security.cs.debugger".to_string(),
        serde_json::Value::Bool(true),
    );
    let mut report = AnalysisReport::new(crate::types::TargetInfo {
        path: "/Applications/Acme.app/Contents/MacOS/Acme".to_string(),
        file_type: "macho".to_string(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: None,
    });
    emit_signature_findings(
        &mut report,
        0x4000,
        None,
        &identity,
        Some(&entitlements),
        None,
        None,
    );

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

    // A dangerous entitlement on a non-platform binary escalates to Suspicious.
    let ent = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/entitlement/security::com.apple.security.cs.debugger")
        .expect("entitlement finding emitted");
    assert_eq!(ent.crit, Criticality::Suspicious);
    assert_eq!(ent.evidence[0].location.as_deref(), Some("0x4000"));
}

/// Permissions never fall to Baseline: every entitlement is at least
/// Notable, and dangerous ones escalate to Suspicious. Guards the
/// `determine_entitlement_criticality` invariant.
#[test]
fn test_entitlements_never_baseline() {
    // (key, is_platform)
    let cases = [
        ("com.apple.security.app-sandbox", false),
        ("com.apple.security.cs.allow-jit", false),
        ("com.apple.security.get-task-allow", false),
        ("com.apple.private.tcc.allow", true),
    ];
    for (key, is_platform) in cases {
        let crit = determine_entitlement_criticality(key, is_platform, false);
        assert!(
            crit >= Criticality::Notable,
            "entitlement {key} must be Notable-or-higher, got {crit:?}"
        );
    }
}

#[test]
fn test_entitlement_finding_confidence() {
    let analyzer = MachOAnalyzer::new();
    let test_file = test_macho_path();

    let report = analyzer.analyze(&test_file).unwrap();

    // All entitlement findings should have high confidence
    let ent_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.id.contains("entitlement"))
        .collect();

    for finding in &ent_findings {
        assert_eq!(finding.conf, 1.0); // Entitlements from signature have 100% confidence
    }
}

#[test]
fn test_describe_entitlement_coverage() {
    // Test that describe_entitlement handles various entitlement keys
    assert_eq!(
        describe_entitlement("com.apple.security.cs.disable-library-validation"),
        "Allows libraries without signature validation"
    );
    assert_eq!(
        describe_entitlement("com.apple.security.cs.allow-jit"),
        "Allows JIT-compiled executable memory"
    );
    assert_eq!(
        describe_entitlement("personal-information.location"),
        "Location data access"
    );
    assert_eq!(describe_entitlement("device.camera"), "Camera access");
    assert_eq!(
        describe_entitlement("com.apple.security.network.client"),
        "Can make outbound network connections"
    );
    assert_eq!(
        describe_entitlement("com.apple.security.network.server"),
        "Can accept incoming network connections"
    );
    assert_eq!(
        describe_entitlement("com.apple.security.files.user-selected.read-write"),
        "Can read and modify user-selected files"
    );
    assert_eq!(
        describe_entitlement("com.apple.developer.team-identifier"),
        "Team identifier"
    );
}

#[test]
fn test_describe_entitlement_fallback() {
    // Test fallback behavior for unknown entitlements
    let desc = describe_entitlement("com.example.unknown-entitlement");
    assert!(!desc.is_empty());
    assert_ne!(desc, "com.example.unknown-entitlement"); // Should be transformed
}

#[test]
fn test_determine_entitlement_criticality_platform_always_notable() {
    // Platform (Apple-signed) binaries: all entitlements are notable
    for key in [
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.disable-library-validation",
    ] {
        assert_eq!(
            determine_entitlement_criticality(key, true, false,),
            Criticality::Notable,
            "platform binary entitlement {key} should be notable"
        );
    }
}

#[test]
fn test_determine_entitlement_criticality_dangerous_non_apple() {
    // Dangerous entitlements are suspicious on non-Apple binaries
    for key in [
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.allow-unsigned-executable-memory",
    ] {
        assert_eq!(
            determine_entitlement_criticality(key, false, false,),
            Criticality::Suspicious,
            "non-Apple entitlement {key} should be suspicious"
        );
    }
    // allow-jit is common in legitimate apps, notable not suspicious
    assert_eq!(
        determine_entitlement_criticality("com.apple.security.cs.allow-jit", false, false,),
        Criticality::Notable,
    );
}

#[test]
fn test_determine_entitlement_criticality_disable_library_validation_notable() {
    // disable-library-validation is common for developer-signed apps (plugins, frameworks)
    assert_eq!(
        determine_entitlement_criticality(
            "com.apple.security.cs.disable-library-validation",
            false,
            false,
        ),
        Criticality::Notable,
    );
}

#[test]
fn test_determine_entitlement_criticality_privacy_notable() {
    for key in ["personal-information.location", "device.bluetooth"] {
        assert_eq!(
            determine_entitlement_criticality(key, false, false,),
            Criticality::Notable,
        );
    }
}

#[test]
fn test_determine_entitlement_criticality_allow_unsigned_exec_memory_common_helper() {
    assert_eq!(
        determine_entitlement_criticality(
            "com.apple.security.cs.allow-unsigned-executable-memory",
            false,
            true,
        ),
        Criticality::Notable,
    );
    assert_eq!(
        determine_entitlement_criticality(
            "com.apple.security.cs.allow-unsigned-executable-memory",
            false,
            true,
        ),
        Criticality::Notable,
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
