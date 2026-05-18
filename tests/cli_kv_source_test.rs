//! End-to-end test for `cleave kv` over a tree-sitter source file.
//!
//! Pins the contract that source-code files (here: a tiny `.c`) flow
//! through the unified analyzer and surface a `source.*` kv subtree
//! with imports, functions, and strings populated. A regression in
//! `tree-sitter-c`, `extract_c_import`, or `source_kv::attach_to_report`
//! would silently zero out `source.imports` for every C file in the
//! wild — this test catches that.
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

    let mut cmd = assert_cmd::cargo_bin_cmd!("cleave");
    cmd.env("CLEAVE_SKIP_YARA", "1")
        .args(["--json", "kv", path.to_str().unwrap()]);
    let output = cmd.output().expect("run cleave kv");
    assert!(
        output.status.success(),
        "cleave kv exited {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let entries: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse kv json");
    let arr = entries.as_array().expect("entries array");
    let paths: Vec<&str> = arr.iter().map(|e| e["path"].as_str().unwrap()).collect();

    // The unified analyzer populated `source.*` from the file's call
    // sites and string constants. Assert the keys trait authors rely on.
    assert!(
        paths.iter().any(|p| p.starts_with("source.imports[")),
        "missing source.imports[*]: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p.starts_with("source.functions[")),
        "missing source.functions[*]: {paths:?}"
    );
    assert!(
        paths.contains(&"source.has_imports"),
        "missing source.has_imports flag: {paths:?}"
    );

    // The `system` and `execl` call sites should both surface as imports —
    // a single-call regression would still pass a "non-empty" check but
    // miss the multi-call-site path through `extract_c_import`.
    let imports: Vec<&str> = arr
        .iter()
        .filter(|e| {
            e["path"]
                .as_str()
                .is_some_and(|p| p.starts_with("source.imports["))
        })
        .filter_map(|e| e["value"].as_str())
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
        "kv",
        path.to_str().unwrap(),
        "--path",
        "source.imports",
    ]);
    let output = cmd.output().expect("run cleave kv");
    assert!(
        output.status.success(),
        "cleave kv with --path exited {}: stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let entries: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse kv json");
    let arr = entries.as_array().expect("entries array");
    // Every returned entry must live under the requested prefix —
    // confirms the filter applies to source-file kv output the same way
    // it does to office / structured-document trees.
    for entry in arr {
        let p = entry["path"].as_str().unwrap();
        assert!(
            p.starts_with("source.imports"),
            "filtered path leaked outside prefix: {p}"
        );
    }
}
