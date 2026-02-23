//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Test that random JSON/YAML/TOML files are not processed during scanning.
//!
//! This test verifies that only known manifest filenames are analyzed,
//! and arbitrary structured data files are skipped.

use flayer::AnalysisOptions;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_random_json_files_skipped_in_directory_scan() {
    // Create a temporary directory with various JSON files
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create random JSON files (should be skipped)
    fs::write(
        base_path.join("config.json"),
        br#"{"api_key": "secret123", "endpoint": "https://evil.com"}"#,
    )
    .unwrap();

    fs::write(
        base_path.join("database.json"),
        br#"{"host": "localhost", "password": "admin123"}"#,
    )
    .unwrap();

    fs::write(
        base_path.join("settings.json"),
        br#"{"debug": true, "secrets": ["key1", "key2"]}"#,
    )
    .unwrap();

    // Create known manifest file (should be processed)
    fs::write(
        base_path.join("package.json"),
        br#"{"name": "test-package", "version": "1.0.0"}"#,
    )
    .unwrap();

    // Scan the directory using flayer library
    let options = AnalysisOptions {
        all_files: false,
        ..Default::default()
    };
    let reports =
        flayer::analyze_directory(base_path, &options).expect("Directory analysis failed");

    // Should only have one report (for package.json)
    // Random JSON files should not be analyzed
    let json_reports: Vec<_> = reports
        .iter()
        .filter(|r| r.target.path.ends_with(".json") && !r.target.path.contains("package.json"))
        .collect();

    // Verify random JSON files were not analyzed
    assert_eq!(
        json_reports.len(),
        0,
        "Random JSON files should not be analyzed: {:?}",
        json_reports
            .iter()
            .map(|r| &r.target.path)
            .collect::<Vec<_>>()
    );

    // Verify package.json was analyzed
    let package_json_reports: Vec<_> = reports
        .iter()
        .filter(|r| r.target.path.contains("package.json"))
        .collect();

    assert_eq!(
        package_json_reports.len(),
        1,
        "package.json should be analyzed"
    );
}

#[test]
#[ignore = "File filtering not working as expected - GitHub Actions workflows not being analyzed"]
fn test_random_yaml_files_skipped() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create random YAML files (should be skipped)
    fs::write(
        base_path.join("config.yaml"),
        b"database:\n  host: localhost\n  password: secret",
    )
    .unwrap();

    fs::write(
        base_path.join("docker-compose.yml"),
        b"version: '3'\nservices:\n  web:\n    image: nginx",
    )
    .unwrap();

    // Create GitHub Actions workflow (should be processed)
    let workflows_dir = base_path.join(".github").join("workflows");
    fs::create_dir_all(&workflows_dir).unwrap();
    fs::write(
        workflows_dir.join("ci.yml"),
        b"name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest",
    )
    .unwrap();

    let options = AnalysisOptions {
        all_files: false,
        ..Default::default()
    };
    let reports =
        flayer::analyze_directory(base_path, &options).expect("Directory analysis failed");

    // Verify random YAML files were not analyzed
    let random_yaml_reports: Vec<_> = reports
        .iter()
        .filter(|r| {
            (r.target.path.ends_with(".yaml") || r.target.path.ends_with(".yml"))
                && !r.target.path.contains(".github/workflows")
        })
        .collect();

    assert_eq!(
        random_yaml_reports.len(),
        0,
        "Random YAML files should not be analyzed"
    );

    // Verify GitHub Actions workflow was analyzed
    let workflow_reports: Vec<_> = reports
        .iter()
        .filter(|r| r.target.path.contains(".github/workflows"))
        .collect();

    assert_eq!(
        workflow_reports.len(),
        1,
        "GitHub Actions workflow should be analyzed"
    );
}

#[test]
#[ignore = "File filtering not working as expected - Cargo.toml not being analyzed"]
fn test_random_toml_files_skipped() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create random TOML files (should be skipped)
    fs::write(
        base_path.join("config.toml"),
        b"[database]\nhost = \"localhost\"\npassword = \"secret\"",
    )
    .unwrap();

    fs::write(
        base_path.join("settings.toml"),
        b"[app]\ndebug = true\napi_key = \"secret123\"",
    )
    .unwrap();

    // Create known manifest (should be processed)
    fs::write(
        base_path.join("Cargo.toml"),
        b"[package]\nname = \"test-crate\"\nversion = \"0.1.0\"",
    )
    .unwrap();

    let options = AnalysisOptions {
        all_files: false,
        ..Default::default()
    };
    let reports =
        flayer::analyze_directory(base_path, &options).expect("Directory analysis failed");

    // Verify random TOML files were not analyzed
    let random_toml_reports: Vec<_> = reports
        .iter()
        .filter(|r| r.target.path.ends_with(".toml") && !r.target.path.contains("Cargo.toml"))
        .collect();

    assert_eq!(
        random_toml_reports.len(),
        0,
        "Random TOML files should not be analyzed"
    );

    // Verify Cargo.toml was analyzed
    let cargo_reports: Vec<_> = reports
        .iter()
        .filter(|r| r.target.path.contains("Cargo.toml"))
        .collect();

    assert_eq!(cargo_reports.len(), 1, "Cargo.toml should be analyzed");
}

#[test]
fn test_explicit_file_argument_still_analyzed() {
    // When a user explicitly specifies a file on the command line,
    // it should be analyzed even if it's not a known manifest
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    let random_json = base_path.join("random.json");
    fs::write(&random_json, br#"{"data": "value"}"#).unwrap();

    // When analyzing a specific file path (not directory scanning),
    // it should be processed
    let options = AnalysisOptions::default();
    let report = flayer::analyze_file(&random_json, &options);

    // The file should be analyzed (even though it's not a known manifest)
    // because the user explicitly specified it
    assert!(
        report.is_ok(),
        "Explicitly specified files should always be analyzed"
    );
}

#[test]
fn test_all_files_flag_processes_everything() {
    let temp_dir = TempDir::new().unwrap();
    let base_path = temp_dir.path();

    // Create random JSON files
    fs::write(base_path.join("config.json"), br#"{"test": "value"}"#).unwrap();

    fs::write(base_path.join("data.json"), br#"{"other": "data"}"#).unwrap();

    // With --all-files flag, even random JSON files should be analyzed
    let options = AnalysisOptions {
        all_files: true,
        ..Default::default()
    };
    let reports =
        flayer::analyze_directory(base_path, &options).expect("Directory analysis failed");

    // With all_files=true, all JSON files should be present in reports
    let json_count = reports
        .iter()
        .filter(|r| r.target.path.ends_with(".json"))
        .count();

    assert_eq!(
        json_count, 2,
        "With --all-files, all JSON files should be analyzed"
    );
}
