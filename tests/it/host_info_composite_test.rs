//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Test for host_info_strings composite rule
/// This test specifically debugs why the composite rule doesn't fire
use cleave::capabilities::CapabilityMapper;
use cleave::types::{AnalysisReport, TargetInfo};

#[test]
fn test_host_info_composite_fires_with_4_atomics() {
    // Create a test report with host info strings
    let mut report = AnalysisReport::new(TargetInfo {
        path: "test.elf".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    });

    // Add strings that should match the host info atomic traits
    report.strings = vec![
        cleave::types::StringInfo {
            value: ("LanIP: 192.168.1.1".to_string()).into(),
            offset: Some(0x100),
            encoding: "ascii".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        },
        cleave::types::StringInfo {
            value: ("GateWay: 192.168.1.254".to_string()).into(),
            offset: Some(0x200),
            encoding: "ascii".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        },
        cleave::types::StringInfo {
            value: ("OSInfo: Linux".to_string()).into(),
            offset: Some(0x300),
            encoding: "ascii".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        },
        cleave::types::StringInfo {
            value: ("Userame: root".to_string()).into(),
            offset: Some(0x400),
            encoding: "ascii".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        },
    ];

    // Load capability mapper with traits
    let mapper = CapabilityMapper::new();

    // Evaluate all rules and merge findings
    let binary_data =
        b"LanIP: 192.168.1.1\x00GateWay: 192.168.1.254\x00OSInfo: Linux\x00Userame: root\x00";
    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    // Debug: Print all findings
    println!("\n=== All findings ({}) ===", report.findings.len());
    for f in &report.findings {
        println!("  {}: {} ({:?})", f.id, f.desc, f.crit);
    }

    // Check that atomic traits were detected
    let atomic_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            f.id.contains("lanip-label")
                || f.id.contains("gateway-label")
                || f.id.contains("osinfo-label")
                || f.id.contains("userame-label-typo")
        })
        .collect();

    println!(
        "\n=== Atomic host info traits ({}) ===",
        atomic_findings.len()
    );
    for f in &atomic_findings {
        println!("  {}: {:?}", f.id, f.crit);
    }

    assert!(
        atomic_findings.len() >= 3,
        "Expected at least 3 atomic host info traits, found {}",
        atomic_findings.len()
    );

    // Check that composite rule was triggered
    let composite = report
        .findings
        .iter()
        .find(|f| f.id.contains("host_info_strings"));

    println!("\n=== Composite rule ===");
    if let Some(comp) = composite {
        println!("  Found: {}", comp.id);
        println!("  Evidence count: {}", comp.evidence.len());
    } else {
        println!("  NOT FOUND!");

        // Debug: Check all discovery/fingerprint/system findings
        let system_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.starts_with("discovery/fingerprint/system"))
            .collect();

        println!("\n=== All discovery/fingerprint/system findings ===");
        for f in system_findings {
            println!("  {}", f.id);
        }
    }

    assert!(
        composite.is_some(),
        "Expected host_info_strings composite rule to fire with {} atomic traits",
        atomic_findings.len()
    );

    // Verify evidence propagated
    if let Some(comp) = composite {
        assert!(
            !comp.evidence.is_empty(),
            "Composite rule should have evidence"
        );
    }
}
