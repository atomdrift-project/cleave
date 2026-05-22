//! End-to-end test for `cleave value` over a tree-sitter source file.
//!
//! Pins the contract that source-code files keep residual `source.*` values
//! small while imports/functions live in their own typed command output.
//! This catches accidental re-duplication of symbols into `cleave value`
//! and verifies source imports still surface through `cleave imports`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn cleave_kv_emits_source_subtree_for_c() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sample.c");
    std::fs::write(
        &path,
        r#"#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char *cmd = "/bin/sh";
    execl(cmd, cmd, "-c", "echo hi", NULL);
    system("curl http://example.com");
    return 0;
}
"#,
    )
    .unwrap();

    let mut value_cmd = assert_cmd::cargo_bin_cmd!("cleave");
    value_cmd
        .env("CLEAVE_SKIP_YARA", "1")
        .args(["--json", "value", path.to_str().unwrap()]);
    let value_output = value_cmd.output().expect("run cleave value");
    assert!(
        value_output.status.success(),
        "cleave value exited {}: stderr={}",
        value_output.status,
        String::from_utf8_lossy(&value_output.stderr)
    );

    let entries: serde_json::Value =
        serde_json::from_slice(&value_output.stdout).expect("parse value json");
    let arr = entries.as_array().expect("entries array");
    let paths: Vec<&str> = arr.iter().map(|e| e["path"].as_str().unwrap()).collect();

    assert!(
        paths.contains(&"source.language"),
        "missing source.language: {paths:?}"
    );
    assert!(
        paths.iter().all(|p| !p.starts_with("source.imports[")),
        "imports must not be duplicated into values: {paths:?}"
    );
    assert!(
        paths.iter().all(|p| !p.starts_with("source.functions[")),
        "functions must not be duplicated into values: {paths:?}"
    );

    let mut imports_cmd = assert_cmd::cargo_bin_cmd!("cleave");
    imports_cmd
        .env("CLEAVE_SKIP_YARA", "1")
        .args(["--json", "imports", path.to_str().unwrap()]);
    let imports_output = imports_cmd.output().expect("run cleave imports");
    assert!(
        imports_output.status.success(),
        "cleave imports exited {}: stderr={}",
        imports_output.status,
        String::from_utf8_lossy(&imports_output.stderr)
    );

    let import_entries: serde_json::Value =
        serde_json::from_slice(&imports_output.stdout).expect("parse imports json");
    let imports: Vec<&str> = import_entries
        .as_array()
        .expect("imports array")
        .iter()
        .filter_map(|entry| entry["name"].as_str())
        .collect();
    assert!(
        imports.contains(&"system"),
        "expected `system` in imports: {imports:?}"
    );
    assert!(
        imports.contains(&"execl"),
        "expected `execl` in imports: {imports:?}"
    );
}

#[test]
fn cleave_kv_path_filter_works_on_source_files() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sample.c");
    std::fs::write(&path, "int main(void) { puts(\"hi\"); return 0; }\n").unwrap();

    let mut cmd = assert_cmd::cargo_bin_cmd!("cleave");
    cmd.env("CLEAVE_SKIP_YARA", "1").args([
        "--json",
        "value",
        path.to_str().unwrap(),
        "--path",
        "source.language",
    ]);
    let output = cmd.output().expect("run cleave value");
    assert!(
        output.status.success(),
        "cleave value with --path exited {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let entries: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse value json");
    let arr = entries.as_array().expect("entries array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["path"], "source.language");
    assert_eq!(arr[0]["value"], "c");
}
