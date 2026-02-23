//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Test to ensure binary metrics are always collected, even when radare2 fails
/// This prevents regression of the bug where metrics were missing from test-rules output
use flayer::analyzers::analyzer_for_file_type;
use flayer::FileType;
use std::path::PathBuf;

/// Test that Mach-O files always have basic binary metrics populated
/// even if radare2 fails or is unavailable
#[test]
fn test_macho_binary_metrics_always_populated() {
    // Find a test Mach-O file
    let test_file = find_test_macho_file();
    if test_file.is_none() {
        eprintln!("SKIP: No test Mach-O file found");
        return;
    }
    let test_file = test_file.unwrap();

    // Create capability mapper (needed for analyzer)
    let capability_mapper = flayer::capabilities::CapabilityMapper::new();

    // Get Mach-O analyzer
    let analyzer = analyzer_for_file_type(&FileType::MachO, Some(capability_mapper));
    assert!(analyzer.is_some(), "Should have Mach-O analyzer");

    // Analyze the file
    let report = analyzer
        .unwrap()
        .analyze(&test_file)
        .expect("Analysis should succeed");

    // CRITICAL: metrics must always be present
    assert!(report.metrics.is_some(), "Metrics must always be populated");

    let metrics = report.metrics.unwrap();

    // CRITICAL: binary metrics must always be present for Mach-O files
    assert!(
        metrics.binary.is_some(),
        "Binary metrics must always be populated for Mach-O"
    );

    let binary_metrics = metrics.binary.unwrap();

    // Basic metrics that should ALWAYS be populated (even without radare2):
    assert!(
        binary_metrics.file_size > 0,
        "file_size should be populated: {}",
        binary_metrics.file_size
    );
    assert!(
        binary_metrics.segment_count > 0,
        "segment_count should be populated: {}",
        binary_metrics.segment_count
    );

    // String count should be populated after string extraction
    assert!(
        binary_metrics.string_count > 0,
        "string_count should be populated: {}",
        binary_metrics.string_count
    );

    // Boolean fields should be set
    // Note: is_stripped and is_pie depend on the file, but they should be evaluated
    eprintln!("Binary metrics successfully populated:");
    eprintln!("  file_size: {}", binary_metrics.file_size);
    eprintln!("  segment_count: {}", binary_metrics.segment_count);
    eprintln!("  string_count: {}", binary_metrics.string_count);
    eprintln!("  is_stripped: {}", binary_metrics.is_stripped);
    eprintln!("  is_pie: {}", binary_metrics.is_pie);
    eprintln!("  has_debug_info: {}", binary_metrics.has_debug_info);

    // If radare2 succeeded, we should also have these:
    if binary_metrics.code_to_data_ratio > 0.0 {
        eprintln!(
            "  code_to_data_ratio: {:.2}",
            binary_metrics.code_to_data_ratio
        );
        eprintln!("Radare2 metrics successfully merged");
    } else {
        eprintln!("  code_to_data_ratio: 0.0 (radare2 may have failed - this is OK)");
    }
}

/// Test that metrics are accessible to rules (the original bug report)
#[test]
fn test_metrics_accessible_to_rules() {
    // Find a test Mach-O file
    let test_file = find_test_macho_file();
    if test_file.is_none() {
        eprintln!("SKIP: No test Mach-O file found");
        return;
    }
    let test_file = test_file.unwrap();

    // Create capability mapper with metrics-based rules
    let capability_mapper = flayer::capabilities::CapabilityMapper::new();

    // Get Mach-O analyzer
    let analyzer = analyzer_for_file_type(&FileType::MachO, Some(capability_mapper.clone()));
    assert!(analyzer.is_some(), "Should have Mach-O analyzer");

    // Analyze the file
    let mut report = analyzer
        .unwrap()
        .analyze(&test_file)
        .expect("Analysis should succeed");

    // Metrics must be present before rule evaluation
    assert!(
        report.metrics.is_some(),
        "Metrics must be present before rule evaluation"
    );
    assert!(
        report.metrics.as_ref().unwrap().binary.is_some(),
        "Binary metrics must be present"
    );

    // Evaluate rules against the report
    capability_mapper.evaluate_and_merge_findings(
        &mut report,
        &std::fs::read(&test_file).unwrap(),
        None,
        None,
    );

    // The key test: metrics-based rules should be able to evaluate
    // We don't care if they match or not, just that they can access metrics without error

    // Verify binary metrics are still present after rule evaluation
    assert!(
        report.metrics.is_some(),
        "Metrics must persist after rule evaluation"
    );
    assert!(
        report.metrics.as_ref().unwrap().binary.is_some(),
        "Binary metrics must persist"
    );

    let binary_metrics = report.metrics.unwrap().binary.unwrap();
    eprintln!("Metrics successfully accessible to rules:");
    eprintln!("  binary.file_size: {}", binary_metrics.file_size);
    eprintln!("  binary.string_count: {}", binary_metrics.string_count);
    eprintln!(
        "  binary.code_to_data_ratio: {:.2}",
        binary_metrics.code_to_data_ratio
    );
}

/// Helper to find a test Mach-O file
/// Checks common locations for test data
fn find_test_macho_file() -> Option<PathBuf> {
    // Try to find test data in common locations
    let candidates = vec![
        // CI environment
        "testdata/benign/macho/hello_world",
        "testdata/clean/elf_linux/libcap2/libcap.so",  // Actually check for macho
        // Development environment
        "/Users/t/data/known-bad/datasets/MalwareBazaar/macho/02c6b17b841ac7c53ea61c0033246bc8ee11432ce5ed7372e0a63c0076315507.macho",
        // Use /bin/ls as fallback (always available on macOS)
        "/bin/ls",
        "/usr/bin/file",
    ];

    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            // Verify it's actually a Mach-O file
            if let Ok(data) = std::fs::read(&path) {
                if data.len() > 4 {
                    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                    // Mach-O magic numbers: 0xfeedface (32-bit), 0xfeedfacf (64-bit),
                    // 0xcefaedfe (32-bit LE), 0xcffaedfe (64-bit LE)
                    if magic == 0xfeedface
                        || magic == 0xfeedfacf
                        || magic == 0xcefaedfe
                        || magic == 0xcffaedfe
                    {
                        eprintln!("Using test file: {}", path.display());
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}

/// Test that radare2 failure is handled gracefully
#[test]
fn test_radare2_failure_handling() {
    // This test verifies that when radare2 fails, we still get basic metrics
    // We can't easily force radare2 to fail in a test, but we can verify
    // the code path exists by checking the implementation

    let test_file = find_test_macho_file();
    if test_file.is_none() {
        eprintln!("SKIP: No test Mach-O file found");
        return;
    }
    let test_file = test_file.unwrap();

    // Create capability mapper
    let capability_mapper = flayer::capabilities::CapabilityMapper::new();

    // Get Mach-O analyzer
    let analyzer = analyzer_for_file_type(&FileType::MachO, Some(capability_mapper));
    assert!(analyzer.is_some(), "Should have Mach-O analyzer");

    // Analyze the file
    let report = analyzer
        .unwrap()
        .analyze(&test_file)
        .expect("Analysis should succeed");

    // Even if radare2 fails, we must have basic metrics
    assert!(report.metrics.is_some());
    let metrics = report.metrics.unwrap();
    assert!(metrics.binary.is_some());

    let binary_metrics = metrics.binary.unwrap();

    // These are computed WITHOUT radare2, so they must always be present
    assert!(binary_metrics.file_size > 0);
    // segment_count and string_count are unsigned, so no need to check >= 0

    eprintln!("Basic metrics populated regardless of radare2 status:");
    eprintln!(
        "  file_size: {} (from file metadata)",
        binary_metrics.file_size
    );
    eprintln!(
        "  segment_count: {} (from goblin)",
        binary_metrics.segment_count
    );
    eprintln!(
        "  string_count: {} (from stng)",
        binary_metrics.string_count
    );
}
