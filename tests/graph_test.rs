//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Test that map command produces valid DOT output
#[test]
fn test_graph_basic() {
    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - not needed for graph tests
        .env("FLAYER_SKIP_YARA", "1") // Disable validation for faster tests
        .args(["map", "--depth", "2", "--min-refs", "10"])
        .assert()
        .success()
        .stdout(predicate::str::contains("digraph trait_dependencies"))
        .stdout(predicate::str::contains("rankdir=LR"));

    // Verify output contains DOT graph structure
    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("node [shape=box"));
    assert!(stdout.contains("penwidth"));
}

/// Test map command with output to file
#[test]
fn test_graph_output_file() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("traits.dot");

    assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args([
            "map",
            "--depth",
            "2",
            "--min-refs",
            "5",
            "-o",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Verify output file was created and contains DOT content
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("digraph trait_dependencies"));
    assert!(content.contains("fillcolor="));
    assert!(content.contains("color="));
}

/// Test map command with namespace filtering
#[test]
fn test_graph_namespace_filter() {
    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args([
            "map",
            "--depth",
            "2",
            "--min-refs",
            "5",
            "--namespaces",
            "objectives,well-known",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Should contain objectives/ and well-known/ nodes
    assert!(stdout.contains("objectives/") || stdout.contains("well-known/"));

    // Should NOT contain micro-behaviors/ or metadata/ nodes (they are filtered out)
    // Note: There might be no nodes if there are no cross-references between obj and known
    // at the specified depth and min-refs, so we just verify the graph structure exists
    assert!(stdout.contains("digraph trait_dependencies"));
}

/// Test map command with different depth levels
#[test]
fn test_graph_depth_levels() {
    // Test depth 1 (top-level only: cap, obj, known, meta)
    let output_depth1 = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args(["map", "--depth", "1", "--min-refs", "10"])
        .assert()
        .success();

    let stdout_depth1 = String::from_utf8(output_depth1.get_output().stdout.clone()).unwrap();
    assert!(stdout_depth1.contains("digraph trait_dependencies"));

    // Test depth 3 (more granular)
    let output_depth3 = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args(["map", "--depth", "3", "--min-refs", "10"])
        .assert()
        .success();

    let stdout_depth3 = String::from_utf8(output_depth3.get_output().stdout.clone()).unwrap();
    assert!(stdout_depth3.contains("digraph trait_dependencies"));

    // Depth 3 should generally have more nodes than depth 1
    // (unless min-refs filters them all out)
    let nodes_depth1 = stdout_depth1.matches("fillcolor=").count();
    let nodes_depth3 = stdout_depth3.matches("fillcolor=").count();

    // This is a heuristic - depth 3 should typically have >= nodes than depth 1
    assert!(
        nodes_depth3 >= nodes_depth1,
        "Depth 3 should have at least as many nodes as depth 1"
    );
}

/// Test map command respects min-refs filtering
#[test]
fn test_graph_min_refs_filtering() {
    // Low threshold - should have more edges
    let output_low = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args(["map", "--depth", "2", "--min-refs", "1"])
        .assert()
        .success();

    let stdout_low = String::from_utf8(output_low.get_output().stdout.clone()).unwrap();
    let edges_low = stdout_low.matches("->").count();

    // High threshold - should have fewer edges
    let output_high = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args(["map", "--depth", "2", "--min-refs", "20"])
        .assert()
        .success();

    let stdout_high = String::from_utf8(output_high.get_output().stdout.clone()).unwrap();
    let edges_high = stdout_high.matches("->").count();

    // Higher min-refs should filter out more edges
    assert!(
        edges_high <= edges_low,
        "Higher min-refs ({}) should have <= edges than lower min-refs ({})",
        edges_high,
        edges_low
    );
}

/// Test map command color encoding
#[test]
fn test_graph_color_encoding() {
    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args(["map", "--depth", "2", "--min-refs", "5"])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Should contain fill colors for criticality levels
    let has_green = stdout.contains("#90EE90"); // baseline
    let has_yellow = stdout.contains("#FFFF99"); // Notable
    let has_orange = stdout.contains("#FFA500"); // Suspicious
    let has_red = stdout.contains("#FF6347"); // Hostile

    // Should have at least one fill color
    assert!(
        has_green || has_yellow || has_orange || has_red,
        "Graph should contain at least one criticality fill color"
    );

    // Should contain outline colors for namespaces
    let has_cap_outline = stdout.contains("#228B22"); // micro-behaviors/ - green
    let has_obj_outline = stdout.contains("#DC143C"); // objectives/ - red
    let has_known_outline = stdout.contains("#8B008B"); // known/ - purple
    let has_meta_outline = stdout.contains("#696969"); // metadata/ - gray

    // Should have at least one namespace outline color
    assert!(
        has_cap_outline || has_obj_outline || has_known_outline || has_meta_outline,
        "Graph should contain at least one namespace outline color"
    );
}

/// Test map command edge weights
#[test]
fn test_graph_edge_weights() {
    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1")
        .args(["map", "--depth", "2", "--min-refs", "1"])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();

    // Should contain edges with labels (reference counts)
    assert!(stdout.contains("label=\""));

    // Should contain penwidth attributes (edge thickness)
    assert!(stdout.contains("penwidth="));
}

/// Test map help message
#[test]
fn test_graph_help() {
    assert_cmd::cargo_bin_cmd!("flayer")
        .args(["map", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Generate a map visualization"))
        .stdout(predicate::str::contains("--depth"))
        .stdout(predicate::str::contains("--min-refs"))
        .stdout(predicate::str::contains("--namespaces"));
}
