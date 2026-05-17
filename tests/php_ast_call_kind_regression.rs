//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Regression tests for two engine quirks surfaced while writing PHP
//! supply-chain traits against testdata for the BFunky/http-parser case:
//!
//!   (1) `type: ast kind: call exact: <name>` does not match call
//!       sites. The AST cache stores the full call-expression text
//!       (`curl_exec($ch)`) under the `function_call_expression` node
//!       kind, then `evaluators/ast.rs` compares that text via `==`
//!       against the `exact:` pattern (`curl_exec`), which never
//!       succeeds. The symbol extractor in `analyzers/unified.rs`
//!       uses `function_name_field` to grab just the name — that path
//!       is what `cleave symbols` reports, and what `type: symbol
//!       exact: <name>` traits hit. Fixing this engine-side risks
//!       inflating `match_count`/density for existing `substr:` rules,
//!       so the test is `#[ignore]`d and the canonical workaround in
//!       trait YAML is `type: symbol`, or for AST specifically
//!       `substr: "<name>("` / `regex: "^<name>\\b"`.
//!
//!   (2) `scope: file` composite rules used to never fire when AST
//!       evidence was involved. AST locations are pure `row:col`
//!       strings with no file path; `Scope::File.key` returned that
//!       unchanged, so every AST match landed in its own bucket while
//!       sibling evidence (text/symbol/encoded with `location: None`)
//!       bucketed to the empty key. `min_distinct_conditions` could
//!       not be reached even when every primitive matched in the same
//!       file. Fixed in `composite_rules/traits.rs::strip_decode_suffix`
//!       by collapsing positional-only locations to the empty key.
//!
//! Both tests use a single fixture per language and run the production
//! CLI against a temp traits dir so the repros are end-to-end and
//! stable against internal refactors.

use std::fs;
use std::process::Command;
use tempfile::TempDir;

fn cleave_bin() -> &'static str {
    env!("CARGO_BIN_EXE_cleave")
}

const PHP_FIXTURE: &str = r#"<?php
namespace Test;

class Beacon {
  const URL_DIGEST = "aHR0cHM6Ly80NC4yMTAuOTQuMzgvcGFja2FnaXN0LnBocA==";
  public function send() {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, base64_decode(self::URL_DIGEST));
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_exec($ch);
  }
}

$b = new Beacon();
$b->send();
"#;

/// Write a synthetic PHP fixture and a custom traits directory
/// containing exactly the rules under test. Returns the temp dir
/// (kept alive for the duration of the caller) and the fixture path.
fn fixture_with_traits(traits_yaml: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();

    let file = dir.path().join("Analytics.php");
    fs::write(&file, PHP_FIXTURE).unwrap();

    let traits_dir = dir.path().join("traits").join("micro-behaviors").join("test");
    fs::create_dir_all(&traits_dir).unwrap();
    fs::write(traits_dir.join("traits.yaml"), traits_yaml).unwrap();

    (dir, file)
}

fn run_test_rules(dir: &std::path::Path, file: &std::path::Path, rules: &str) -> String {
    let traits = dir.join("traits");
    let out = Command::new(cleave_bin())
        .args([
            "--traits-dir",
            traits.to_str().unwrap(),
            "test-rules",
            file.to_str().unwrap(),
            "--rules",
            rules,
        ])
        .output()
        .expect("cleave test-rules failed to launch");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// True only when the per-rule summary line begins with `MATCHED ` —
/// `"NOT MATCHED <id>"` contains the substring `"MATCHED <id>"` so a
/// naive `contains()` check silently passes the failure case.
fn rule_matched(stdout: &str, rule_id: &str) -> bool {
    stdout
        .lines()
        .any(|line| line.starts_with(&format!("MATCHED {rule_id}")))
}

/// Bug 1: `type: ast kind: call exact: curl_exec` does not match a
/// call site for `curl_exec($ch);` in a PHP file even though the
/// symbol extractor sees the call (`cleave symbols` lists
/// `curl_exec`). Ignored because the safe fix is in trait YAML
/// (`type: symbol` or `substr: "name("`); see the module doc.
#[test]
#[ignore = "documented quirk — use type: symbol or substr: \"name(\" workaround"]
fn ast_kind_call_exact_matches_php_function_call() {
    let traits = r#"
defaults:
  platforms: [unix, windows]
  for: [php]
traits:
  - id: curl-exec-ast
    desc: curl_exec AST call
    crit: notable
    conf: 0.8
    if:
      type: ast
      kind: call
      exact: curl_exec
  - id: curl-init-ast
    desc: curl_init AST call
    crit: notable
    conf: 0.8
    if:
      type: ast
      kind: call
      exact: curl_init
"#;
    let (dir, file) = fixture_with_traits(traits);

    let stdout = run_test_rules(
        dir.path(),
        &file,
        "micro-behaviors/test::curl-exec-ast,micro-behaviors/test::curl-init-ast",
    );

    assert!(
        rule_matched(&stdout, "micro-behaviors/test::curl-exec-ast"),
        "ast kind=call exact=curl_exec should match a PHP curl_exec() call site.\n\
         The AST cache stores `node.utf8_text` (e.g. `curl_exec($ch)`) and\n\
         compares it via `==` against the `exact:` pattern (`curl_exec`),\n\
         which never succeeds. Use the same `function_name_field` extraction\n\
         that symbol_extraction performs.\n\n\
         Got stdout:\n{stdout}"
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::curl-init-ast"),
        "ast kind=call exact=curl_init should match a PHP curl_init() call site.\n\nGot:\n{stdout}"
    );
}

/// Positive test: the canonical workaround for bug 1 — `type: symbol
/// exact: <name>` — does match a PHP call site. Pins the contract
/// that production traits relying on the symbol extractor (e.g. the
/// `-symbol` mirror traits in `micro-behaviors/communications/http/curl/php.yaml`)
/// keep working.
#[test]
fn type_symbol_exact_matches_php_function_call() {
    let traits = r#"
defaults:
  platforms: [unix, windows]
  for: [php]
traits:
  - id: curl-exec-symbol
    desc: curl_exec symbol present
    crit: notable
    conf: 0.8
    if:
      type: symbol
      exact: curl_exec
  - id: curl-init-via-substr
    desc: curl_init AST substr match
    crit: notable
    conf: 0.8
    if:
      type: ast
      kind: call
      substr: "curl_init("
"#;
    let (dir, file) = fixture_with_traits(traits);

    let stdout = run_test_rules(
        dir.path(),
        &file,
        "micro-behaviors/test::curl-exec-symbol,micro-behaviors/test::curl-init-via-substr",
    );

    assert!(
        rule_matched(&stdout, "micro-behaviors/test::curl-exec-symbol"),
        "type: symbol exact: curl_exec must match the call site that\n\
         `cleave symbols` reports. This is the canonical workaround for\n\
         the AST `exact:` quirk documented in the module header.\n\nGot:\n{stdout}"
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::curl-init-via-substr"),
        "type: ast kind: call substr: \"curl_init(\" must match — substr\n\
         is run against the full call expression text and the trailing\n\
         paren disambiguates from `curl_init_something_else`.\n\nGot:\n{stdout}"
    );
}

/// Bug 2: a composite with `scope: file` over conditions whose
/// evidence carries `path:row:col` locations MUST still fire when all
/// conditions match in the same source file.
///
/// Locations produced by the AST evaluator are pure `"row:col"`
/// strings (see `composite_rules/evaluators/ast.rs`). `Scope::File.key`
/// runs `strip_decode_suffix` which only collapses
/// `encoding_chain:` -prefixed locations; everything else is returned
/// unchanged. So two distinct AST matches in the same file land in
/// distinct scope-key buckets (`"6:14"`, `"7:1"`, …), neither bucket
/// hits `min_distinct_conditions = 2`, and the rule never matches —
/// even though every primitive reports ✓ in the breakdown.
///
/// Use Python here because Python's AST `exact:` matching (with the
/// trailing-`(` convention already used in production traits) works,
/// whereas PHP's is broken by bug 1 above. The scope-filter bug is
/// language-agnostic — it's about what `Scope::File.key` does with
/// AST-evaluator locations.
#[test]
fn scope_file_composite_fires_when_all_conditions_match_same_file() {
    let py_fixture = "import os\neval(\"x\")\nprint(\"y\")\n";

    let dir = TempDir::new().unwrap();
    let file = dir.path().join("scope.py");
    fs::write(&file, py_fixture).unwrap();

    let traits_dir = dir.path().join("traits").join("micro-behaviors").join("test");
    fs::create_dir_all(&traits_dir).unwrap();
    let traits = r#"
defaults:
  platforms: [unix, windows]
  for: [python]
traits:
  - id: eval-ast
    desc: Python eval AST call
    crit: notable
    conf: 0.8
    if:
      type: ast
      kind: call
      substr: "eval("
  - id: print-ast
    desc: Python print AST call
    crit: notable
    conf: 0.8
    if:
      type: ast
      kind: call
      substr: "print("
composite_rules:
  - id: scope-file-pair
    desc: scope file pair test
    crit: suspicious
    conf: 0.9
    for: [python]
    all:
      - id: eval-ast
      - id: print-ast
    scope: file
"#;
    fs::write(traits_dir.join("traits.yaml"), traits).unwrap();

    let stdout = run_test_rules(
        dir.path(),
        &file,
        "micro-behaviors/test::scope-file-pair",
    );

    // Sanity: both primitives should report ✓ in the breakdown.
    assert!(
        stdout.contains("✓ trait: eval-ast")
            || stdout.contains("✓ trait: micro-behaviors/test::eval-ast"),
        "expected eval-ast ✓ in breakdown.\n\nGot:\n{stdout}"
    );
    assert!(
        stdout.contains("✓ trait: print-ast")
            || stdout.contains("✓ trait: micro-behaviors/test::print-ast"),
        "expected print-ast ✓ in breakdown.\n\nGot:\n{stdout}"
    );
    assert!(
        rule_matched(&stdout, "micro-behaviors/test::scope-file-pair"),
        "scope: file composite must match when every AST condition fires in one file.\n\
         `Scope::File.key` keeps `row:col` (from AST evidence) instead of collapsing to the\n\
         file path, so each per-condition evidence lands in its own bucket and\n\
         `min_distinct_conditions` is never reached.\n\nGot stdout:\n{stdout}"
    );
}
