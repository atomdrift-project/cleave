//! Integration test that pins the cached-path behavior of
//! `type: tree-sitter kind: call exact: <name>` traits during a regular
//! `cleave <file>` scan (NOT `test-rules`).
//!
//! `test-rules` always builds a fresh evaluation context with
//! `ast_kind_cache: None`, so its matchers fall through to the
//! uncached AST walk in `eval_ast`. The CapabilityMapper's main scan
//! path pre-populates `ast_kind_cache` in `evaluate_traits.rs` and
//! routes through the cached branch in `eval_ast`, which has
//! historically diverged. This file exercises the cached branch
//! end-to-end and asserts the trait fires as a finding in the
//! JSON output that downstream tooling (and `cleave validate`'s
//! `walked_hostile` checks) actually consume.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn cleave_bin() -> &'static str {
    env!("CARGO_BIN_EXE_cleave")
}

/// Build an isolated traits dir containing a single per-language trait
/// and run a regular `cleave --format=tiny <fixture>` scan. Returns the
/// captured stdout.
fn scan_with_trait(fixture_name: &str, fixture: &str, traits_yaml: &str) -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join(fixture_name);
    fs::write(&file, fixture).unwrap();

    let traits_dir = dir
        .path()
        .join("traits")
        .join("micro-behaviors")
        .join("test");
    fs::create_dir_all(&traits_dir).unwrap();
    fs::write(traits_dir.join("traits.yaml"), traits_yaml).unwrap();

    let traits_root = dir.path().join("traits");
    let out = Command::new(cleave_bin())
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args([
            "--traits-dir",
            traits_root.to_str().unwrap(),
            "--format=tiny",
            file.to_str().unwrap(),
        ])
        .output()
        .expect("cleave failed to launch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "cleave exited with status {:?}\nstdout: {stdout}\nstderr: {stderr}",
        out.status.code()
    );
    (dir, stdout)
}

/// The context-centric tiny format announces a finding on a preceding
/// comment-marker line shaped `{marker} {SEV} {LINE[:COL]|@OFFSET} {desc}`
/// (e.g. `# N 2:1 bare spawn invocation`, `// H @0 …`); the marker is the
/// sample language's line comment. Returns true if any line carries such an
/// annotation with the given severity letter and description.
fn finding_present(stdout: &str, sev: char, desc: &str) -> bool {
    stdout.lines().any(|line| {
        if !line.contains(desc) {
            return false;
        }
        // Find the standalone severity token (`N`/`H`/…) after the marker, then
        // require the following token to be a location (`LINE`, `LINE:COL`, or
        // `@OFFSET`) — the shape that distinguishes an annotation from source.
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok.len() == 1 && tok.starts_with(sev) {
                return tokens.next().is_some_and(|loc| {
                    loc.starts_with('@') || loc.starts_with(|c: char| c.is_ascii_digit())
                });
            }
        }
        false
    })
}

#[test]
fn cached_scan_emits_python_member_call_exact() {
    // Python member-call: `pty.spawn("/bin/sh")`. The pre-populated AST
    // cache must place `pty.spawn` in Evidence.alt_value so that
    // `exact: pty.spawn` matches even though Evidence.value carries the
    // full call text `pty.spawn("/bin/sh")`.
    let (_dir, stdout) = scan_with_trait(
        "fixture.py",
        "import pty\npty.spawn(\"/bin/sh\")\n",
        r#"
defaults:
  platforms: [unix]
  for: [python]
traits:
  - id: pty-spawn-call
    desc: pty.spawn invocation
    crit: notable
    conf: 0.9
    if:
      type: tree-sitter
      kind: call
      exact: pty.spawn
"#,
    );
    assert!(
        finding_present(&stdout, 'N', "pty.spawn invocation"),
        "exact: pty.spawn must surface as a finding from the cached scan path.\n\
         Verified via test-rules; the cached path in CapabilityMapper has \
         historically dropped this match.\n\nGot:\n{stdout}"
    );
}

#[test]
fn cached_scan_emits_python_bare_call_exact() {
    // Bare-name call: `spawn("/bin/sh")`. The bare-name path is the
    // simpler half of the alt_value design: Evidence.value would be
    // `spawn("/bin/sh")`, Evidence.alt_value would be `spawn`.
    let (_dir, stdout) = scan_with_trait(
        "fixture.py",
        "from pty import spawn\nspawn(\"/bin/sh\")\n",
        r#"
defaults:
  platforms: [unix]
  for: [python]
traits:
  - id: bare-spawn-call
    desc: bare spawn invocation
    crit: notable
    conf: 0.9
    if:
      type: tree-sitter
      kind: call
      exact: spawn
"#,
    );
    assert!(
        finding_present(&stdout, 'N', "bare spawn invocation"),
        "exact: spawn must surface as a finding from the cached scan path.\n\nGot:\n{stdout}"
    );
}

#[test]
fn cached_scan_emits_javascript_member_call_exact() {
    let (_dir, stdout) = scan_with_trait(
        "fixture.js",
        "const os = require('os');\nconsole.log(os.hostname());\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [javascript]
traits:
  - id: os-hostname-call
    desc: os.hostname invocation
    crit: notable
    conf: 0.9
    if:
      type: tree-sitter
      kind: call
      exact: os.hostname
"#,
    );
    assert!(
        finding_present(&stdout, 'N', "os.hostname invocation"),
        "exact: os.hostname must surface as a finding from the cached scan path.\n\nGot:\n{stdout}"
    );
}
