//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use predicates::prelude::*;

use std::fs;
use tempfile::TempDir;

/// Test that analyze command handles directories (scans all files)
#[test]

fn test_analyze_command_handles_directory() {
    let temp_dir = TempDir::new().unwrap();
    let subdir = temp_dir.path().join("subdir");
    fs::create_dir_all(&subdir).unwrap();

    fs::write(
        temp_dir.path().join("test1.sh"),
        "#!/bin/bash\necho 'test1'",
    )
    .unwrap();
    fs::write(subdir.join("test2.sh"), "#!/bin/bash\necho 'test2'").unwrap();

    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test1.sh").or(predicate::str::contains("test2.sh")));
}

/// Test that analyze command handles single files
#[test]

fn test_analyze_command_handles_single_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("single-file.sh");
    fs::write(&test_file, "#!/bin/bash\necho 'hello'").unwrap();

    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", test_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("single-file.sh"));
}

/// Test analyze command with multiple paths
#[test]

fn test_analyze_command_handles_multiple_paths() {
    let temp_dir1 = TempDir::new().unwrap();
    let temp_dir2 = TempDir::new().unwrap();

    fs::write(temp_dir1.path().join("file1.sh"), "#!/bin/bash\necho '1'").unwrap();
    fs::write(temp_dir2.path().join("file2.sh"), "#!/bin/bash\necho '2'").unwrap();

    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args([
            "--json",
            "analyze",
            temp_dir1.path().to_str().unwrap(),
            temp_dir2.path().to_str().unwrap(),
        ])
        .assert()
        .success();
}

/// Test analyze on empty directory
#[test]

fn test_analyze_empty_directory() {
    let temp_dir = TempDir::new().unwrap();

    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success();
}

/// Test analyze directory containing an archive
#[test]

fn test_analyze_directory_with_archive() {
    let temp_dir = TempDir::new().unwrap();

    // Create a simple tar.gz archive
    let archive_path = temp_dir.path().join("test.tar.gz");
    let file = fs::File::create(&archive_path).unwrap();
    let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);

    let mut header = tar::Header::new_gnu();
    header.set_path("test.sh").unwrap();
    header.set_size(19);
    header.set_cksum();
    tar.append(&header, b"#!/bin/bash\necho 'x'".as_ref())
        .unwrap();
    tar.finish().unwrap();

    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success();
}

/// Test that nonexistent paths fail appropriately
#[test]

fn test_analyze_nonexistent_path() {
    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["analyze", "/tmp/flayer-nonexistent-path-12345"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("does not exist").or(predicate::str::contains("not found")),
        );
}

/// Test symlink handling
#[test]

fn test_analyze_symlink_handling() {
    use std::os::unix::fs::symlink;

    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("target.sh");
    let link = temp_dir.path().join("link.sh");

    fs::write(&target, "#!/bin/bash\necho 'target'").unwrap();
    symlink(&target, &link).unwrap();

    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", link.to_str().unwrap()])
        .assert()
        .success();
}

/// Test deeply nested directories
#[test]

fn test_recursive_depth() {
    let temp_dir = TempDir::new().unwrap();

    // Create 5 levels deep
    let deep_path = temp_dir.path().join("a/b/c/d/e");
    fs::create_dir_all(&deep_path).unwrap();
    fs::write(deep_path.join("deep.sh"), "#!/bin/bash\necho 'deep'").unwrap();

    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("flayer")
        .unwrap()
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("deep.sh"));
}
