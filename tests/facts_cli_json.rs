//! Facts output must remain JSON even when --format is omitted.
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[test]
fn default_facts_json_preserves_control_characters() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("probe.js");
    std::fs::write(&path, "const marker = \"a\u{7f}\u{85}\u{202e}z\";\n").unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_cleave"))
        .args(["--disable", "yara,radare2,third-party", "facts"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(result.status.success(), "{:?}", result.stderr);
    let facts: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        facts["literals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| { v["value"].as_str() == Some("a\u{7f}\u{85}\u{202e}z") })
    );
}
