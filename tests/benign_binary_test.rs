//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Integration test for analyzing benign system binaries.
///
/// Ensures that legitimate system binaries like /bin/ls are correctly
/// classified as baseline/notable without false positive hostile/suspicious findings.
use assert_cmd::Command;
use serde_json::Value;
use std::time::Duration;

#[test]
#[ignore = "Test times out in debug builds - run with cargo test --release"]
fn test_analyze_bin_ls_json_output() {
    let bin_path = assert_cmd::cargo::cargo_bin!("flayer");
    let mut cmd = Command::new(bin_path);

    let output = cmd
        .args(["--json", "/bin/ls"])
        .timeout(Duration::from_secs(10))
        .output()
        .expect("Failed to execute flayer");

    // Should succeed
    assert!(
        output.status.success(),
        "flayer should successfully analyze /bin/ls"
    );

    // Parse JSON Lines output from stdout (one JSON object per line)
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find the first JSON object (starts with '{')
    let json_start = stdout.find('{').expect("Should find JSON object start");
    let json_output = &stdout[json_start..];

    // Parse as JSON Lines - each line is a separate JSON object
    // For single file analysis, we expect one object
    let parsed: Value =
        serde_json::from_str(json_output.trim()).expect("Output should be valid JSON");

    // The output is a single file object with type: "file"
    assert_eq!(
        parsed["type"].as_str(),
        Some("file"),
        "Expected file type object"
    );

    // Collect findings from the file object
    let mut hostile_count = 0;
    let mut suspicious_count = 0;
    let mut notable_count = 0;
    let mut baseline_count = 0;

    if let Some(findings) = parsed["findings"].as_array() {
        for finding in findings {
            let crit = finding["crit"]
                .as_str()
                .expect("Finding should have criticality");

            match crit {
                "hostile" => hostile_count += 1,
                "suspicious" => suspicious_count += 1,
                "notable" => notable_count += 1,
                "baseline" => baseline_count += 1,
                "component" | "filtered" => {} // Ignore these for benign test
                _ => panic!("Unknown criticality: {}", crit),
            }
        }
    }

    // /bin/ls is a legitimate binary - should have no hostile/suspicious findings
    assert_eq!(
        hostile_count, 0,
        "/bin/ls should not have hostile findings (found {})",
        hostile_count
    );
    assert_eq!(
        suspicious_count, 0,
        "/bin/ls should not have suspicious findings (found {})",
        suspicious_count
    );

    // Should have some notable and baseline findings
    assert!(
        notable_count > 0 || baseline_count > 0,
        "Should have at least some notable or baseline findings (notable={}, baseline={})",
        notable_count,
        baseline_count
    );

    println!(
        "✅ /bin/ls analysis: {} baseline, {} notable, 0 suspicious, 0 hostile",
        baseline_count, notable_count
    );
}

#[test]
#[ignore = "Test times out in debug builds - run with cargo test --release"]
fn test_analyze_bin_ls_completes_quickly() {
    let bin_path = assert_cmd::cargo::cargo_bin!("flayer");
    let mut cmd = Command::new(bin_path);

    let start = std::time::Instant::now();

    let output = cmd
        .args(["--json", "/bin/ls"])
        .timeout(Duration::from_secs(10))
        .output()
        .expect("Failed to execute flayer");

    let elapsed = start.elapsed();

    assert!(
        output.status.success(),
        "flayer should successfully analyze /bin/ls"
    );

    assert!(
        elapsed < Duration::from_secs(10),
        "Analysis should complete within 10 seconds (took {:?})",
        elapsed
    );

    println!("✅ /bin/ls analyzed in {:?}", elapsed);
}
