//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Coverage tests for the `kind: call` AST matcher beyond the basic
//! regression in `php_ast_call_kind_regression.rs`. Each test pins one
//! property of the `Evidence.alt_value` design:
//!
//!   - Cross-language: `exact: <bare-name>` works for every supported
//!     language whose call-node kind is in `ast_kinds::map_kind_to_node_types`.
//!   - No double-count: a `substr:` pattern that matches BOTH the full
//!     call text and the extracted name still counts the call site
//!     once (the whole reason `alt_value` is a sibling field instead of
//!     a second Evidence entry).
//!   - Backward compat: the pre-fix `exact: "name("` workaround still
//!     matches the same call sites it used to (via the primary `value`
//!     path).
//!   - `scope: leaf` regression: positional-only locations must NOT
//!     collapse under leaf, only under file. Pins that the bug-2 fix
//!     didn't widen leaf semantics.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn cleave_bin() -> &'static str {
    env!("CARGO_BIN_EXE_cleave")
}

fn run_with_traits(
    fixture_name: &str,
    fixture: &str,
    traits_yaml: &str,
    rules: &str,
) -> (TempDir, String) {
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
        .args([
            "--traits-dir",
            traits_root.to_str().unwrap(),
            "test-rules",
            file.to_str().unwrap(),
            "--rules",
            rules,
        ])
        .output()
        .expect("cleave test-rules failed to launch");
    (dir, String::from_utf8_lossy(&out.stdout).into_owned())
}

fn rule_matched(stdout: &str, rule_id: &str) -> bool {
    stdout
        .lines()
        .any(|line| line.starts_with(&format!("MATCHED {rule_id}")))
}

/// Extract the per-rule match count from `test-rules` output for a
/// matched rule. The marker line is
/// `MATCHED <id> (...)  <desc>` followed by lines describing the
/// condition; the matcher emits `Found N matching AST node(s)` for
/// AST conditions. We look for that integer.
fn ast_match_count(stdout: &str) -> Option<usize> {
    for line in stdout.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("Found ") else {
            continue;
        };
        let Some((n, _)) = rest.split_once(' ') else {
            continue;
        };
        if let Ok(parsed) = n.parse::<usize>() {
            return Some(parsed);
        }
    }
    None
}

// ============ Cross-language `exact: <bare-name>` coverage ============

#[test]
fn exact_bare_name_matches_python_call() {
    let (_dir, stdout) = run_with_traits(
        "test.py",
        "import platform\nplatform.system()\nplatform.node()\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [python]
traits:
  - id: platform-system
    desc: platform.system exact
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      exact: platform.system
"#,
        "micro-behaviors/test::platform-system",
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::platform-system"),
        "exact: platform.system must match a Python platform.system() call.\n\
         Pre-fix, the AST cache compared `platform.system` against\n\
         `platform.system()` (full call text) and never matched.\n\nGot:\n{stdout}"
    );
}

#[test]
fn exact_bare_name_matches_javascript_call() {
    let (_dir, stdout) = run_with_traits(
        "test.js",
        "const os = require('os');\nconsole.log(os.hostname());\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [javascript]
traits:
  - id: os-hostname
    desc: os.hostname exact
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      exact: os.hostname
"#,
        "micro-behaviors/test::os-hostname",
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::os-hostname"),
        "exact: os.hostname must match os.hostname() in JavaScript.\n\nGot:\n{stdout}"
    );
}

#[test]
fn exact_bare_name_matches_go_call() {
    let (_dir, stdout) = run_with_traits(
        "test.go",
        "package main\nimport \"crypto/aes\"\nfunc main() {\n  aes.NewCipher([]byte(\"k\"))\n}\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [go]
traits:
  - id: aes-new-cipher
    desc: aes.NewCipher exact
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      exact: aes.NewCipher
"#,
        "micro-behaviors/test::aes-new-cipher",
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::aes-new-cipher"),
        "exact: aes.NewCipher must match Go aes.NewCipher(...) call.\n\nGot:\n{stdout}"
    );
}

// ============ Single match per call site (no double-count) ============

/// Pattern that matches BOTH the extracted name (`curl_url`) and the
/// full call expression (`curl_url($url)`) must still count the call
/// site exactly once. If we naively pushed two Evidence entries per
/// call node (one for the name, one for the full text), this would
/// count 2 — corrupting `count_min`/`per_kb_min` thresholds in
/// dependent rules.
#[test]
fn substr_overlap_does_not_double_count_call_site() {
    let (_dir, stdout) = run_with_traits(
        "test.php",
        "<?php\n$url = 'x';\ncurl_url($url);\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [php]
traits:
  - id: substr-url
    desc: substr url
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      substr: "url"
"#,
        "micro-behaviors/test::substr-url",
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::substr-url"),
        "expected the rule to match.\n\nGot:\n{stdout}"
    );
    let count = ast_match_count(&stdout).expect("expected `Found N matching AST node(s)` line");
    assert_eq!(
        count, 1,
        "the single call site `curl_url($url)` must count once even though `url` is present\n\
         in both the extracted name (`curl_url`) and the full call text (`curl_url($url)`).\n\
         A higher count means the matcher is pushing two Evidence entries per call node and\n\
         downstream `count_min`/density thresholds will be inflated.\n\nGot stdout:\n{stdout}"
    );
}

// ============ Backward-compat: legitimate pre-fix call-exact usage ============

/// `exact:` on a `kind: call` node has always required full equality
/// against the call expression text. That made `exact: "phpinfo()"` a
/// genuinely working pattern for matching zero-argument calls — the
/// full text really is `phpinfo()`. The fix preserves this: the
/// matcher tries `value` (full text) before falling back to
/// `alt_value` (extracted name), so existing full-text-equal patterns
/// keep firing without going through the name fallback.
#[test]
fn exact_full_zero_arg_call_still_matches() {
    let (_dir, stdout) = run_with_traits(
        "test.php",
        "<?php\nphpinfo();\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [php]
traits:
  - id: phpinfo-full
    desc: phpinfo zero arg
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      exact: "phpinfo()"
"#,
        "micro-behaviors/test::phpinfo-full",
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::phpinfo-full"),
        "exact: \"phpinfo()\" must still match a zero-arg `phpinfo();` call —\n\
         this is the only call shape where pre-fix `exact:` patterns ever\n\
         worked, and the fix must not regress it.\n\nGot:\n{stdout}"
    );
}

/// And `substr: "name("` — the genuinely-working pre-fix idiom — must
/// also keep matching. The full text contains `eval(`, so the primary
/// `value` check fires.
#[test]
fn substr_with_paren_workaround_still_matches() {
    let (_dir, stdout) = run_with_traits(
        "test.py",
        "eval(\"x\")\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [python]
traits:
  - id: eval-substr
    desc: eval substr workaround
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      substr: "eval("
"#,
        "micro-behaviors/test::eval-substr",
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::eval-substr"),
        "substr: \"eval(\" must still match `eval(\"x\")` — this is the\n\
         canonical pre-fix workaround and is documented in RULES.md.\n\nGot:\n{stdout}"
    );
}

// ============ scope: leaf preservation (bug-2 fix did not widen) ============

/// `scope: leaf` is the strictest scope: every evidence item must
/// share the EXACT `Evidence.location`. AST evidence for two different
/// calls has different `row:col` locations; the fix to `Scope::File`
/// must not bleed into `Scope::Leaf`. This test asserts the strict
/// leaf semantics survived.
#[test]
fn scope_leaf_rejects_when_ast_conditions_are_on_different_lines() {
    let (_dir, stdout) = run_with_traits(
        "test.py",
        "eval(\"a\")\nprint(\"b\")\n",
        r#"
defaults:
  platforms: [unix, windows]
  for: [python]
traits:
  - id: eval-ast
    desc: eval ast
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      substr: "eval("
  - id: print-ast
    desc: print ast
    crit: notable
    conf: 0.8
    if:
      type: tree-sitter
      kind: call
      substr: "print("
composite_rules:
  - id: leaf-strict-pair
    desc: leaf strict pair test
    crit: suspicious
    conf: 0.9
    for: [python]
    all:
      - id: eval-ast
      - id: print-ast
    scope: leaf
"#,
        "micro-behaviors/test::leaf-strict-pair",
    );
    assert!(
        !rule_matched(&stdout, "micro-behaviors/test::leaf-strict-pair"),
        "scope: leaf must NOT match when AST conditions land at different\n\
         `row:col` locations. If it does match, the bug-2 fix accidentally\n\
         widened leaf scope semantics to behave like file scope.\n\nGot:\n{stdout}"
    );
}
