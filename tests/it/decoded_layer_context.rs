//! A decoded script layer must carry code windows of its own.
//!
//! Regression guard for the `event-bus-lite-testmetest` npm package: its
//! `index.js` is a ROT-shifted char-code array fed to `eval`, and the decoded
//! layer (`index.js##script@N`) is where the whole payload chain is readable —
//! decrypt, write to a temp dir, spawn. Decoded layers were analyzed outside
//! the orchestration that captures context, so their findings had no windows,
//! and a view that draws annotations only beside code dropped the layer
//! entirely: the one file that showed what the package does.
//!
//! The fixture is inert: the decoded text is never executed, and the marker
//! trait lives in a private traits dir so live rule changes cannot move it.

use std::path::{Path, PathBuf};
use std::process::Command;

const MARKER: &str = "fixture_decoded_layer_marker";

/// The decoded payload: ordinary source a reader should see as code.
fn inner_script() -> String {
    format!(
        "(async()=>{{try{{\n\
         const _fs=await import(\"node:fs\");\n\
         const {MARKER}=_fs.readFileSync(__filename);\n\
         _fs.writeFileSync(\"/dev/null\",{MARKER});\n\
         }}catch(e){{}}}})()\n"
    )
}

/// Encode `inner` the way the package did: shift letters back by one so the
/// wrapper's ROT-1 restores them, then spell the result as char codes.
fn wrapped(inner: &str) -> String {
    let codes = inner
        .chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a') + 25) % 26 + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A') + 25) % 26 + b'A') as char,
            c => c,
        })
        .map(|c| (c as u32).to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "(function(){{try{{eval((function(d,k){{return d.replace(/[a-zA-Z]/g,function(v){{\
         var o=v<=\"Z\"?65:97;return String.fromCharCode((v.charCodeAt(0)-o+k)%26+o)}})}})\
         ([{codes}].map(function(x){{return String.fromCharCode(x)}}).join(\"\"),1))}}catch(_){{}}}})();\n"
    )
}

fn setup(root: &Path) -> PathBuf {
    let rules = root.join("metadata/test/decoded-layer");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("marker.yaml"),
        format!(
            r#"
defaults:
  platforms: [unix, windows]
traits:
  - id: marker
    desc: Decoded layer marker
    crit: notable
    conf: 1.0
    for: [javascript]
    if: {{type: text, substr: {MARKER}}}
"#
        ),
    )
    .unwrap();
    let source = wrapped(&inner_script());
    assert!(
        !source.contains(MARKER),
        "the marker must exist only once decoded"
    );
    let path = root.join("index.js");
    std::fs::write(&path, source).unwrap();
    path
}

fn analyze(root: &Path, path: &Path) -> Vec<u8> {
    let result = Command::new(env!("CARGO_BIN_EXE_cleave"))
        .args([
            "--traits-dir",
            root.to_str().unwrap(),
            "--disable",
            "yara,upx",
            "--format",
            "json",
            "analyze",
            path.to_str().unwrap(),
        ])
        .env("CLEAVE_SKIP_CACHE", "1")
        .env("CLEAVE_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}

#[test]
fn decoded_script_layer_captures_windows_on_its_own_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = setup(dir.path());
    let loaded = cleave::report_input::decode(&analyze(dir.path(), &path)).unwrap();

    let layer = loaded
        .report
        .files
        .iter()
        .find(|f| f.path.contains("##"))
        .expect("the eval payload is decoded into its own layer");
    assert!(
        layer
            .findings
            .iter()
            .any(|f| f.id.contains("decoded-layer::marker")),
        "the marker matches in the decoded text: {:?}",
        layer.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
    );
    let line = format!("const {MARKER}=_fs.readFileSync(__filename);");
    assert!(
        layer
            .context
            .iter()
            .any(|window| String::from_utf8_lossy(&window.data).contains(&line)),
        "a decoded layer must capture windows on its own text: {:?}",
        layer.context
    );
}
