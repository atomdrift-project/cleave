//! Regression tests for `query:` → `type: symbol` / `type: metrics` trait
//! migrations.
//!
//! The migration replaced per-file tree-sitter cursor walks with matches
//! against pre-extracted facts (`cleave facts` symbol/call/member projections)
//! and inline AST metrics. What has to keep working is the *matcher*: a
//! `kind: call` symbol match with a receiver regex, a `kind: import` match
//! narrowed by `alias:`, and `type: metrics` thresholds over counters the AST
//! walk maintains. These fixtures are the "no loss of functionality" proof.
//!
//! The traits below are a self-contained fixture written to a temp dir rather
//! than the sibling traits checkout: the assertions are about cleave's matcher,
//! and pointing them at an external repo made them fail when a trait was merely
//! renamed — and silently skip, reporting green, when the checkout was absent.
//! Each fixture trait is copied from the real trait named in its comment.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;
use tempfile::TempDir;

/// Fixture traits, one per migrated matcher shape.
const FIXTURE_TRAITS: &str = r#"
defaults:
  platforms: [unix, windows]
  crit: notable
  conf: 0.9

traits:
  # `micro-behaviors/hardware/display/screen/python::mss-grab`, verbatim.
  # Matches `.grab` only on mss-style capture receivers, against the
  # pre-extracted `call` fact — the tightening that keeps `queue.grab()` /
  # `lock.grab()` out, which the old bare `.grab` query caught.
  - id: fx-mss-grab
    desc: mss screen capture
    conf: 0.95
    for: [python]
    if:
      type: symbol
      kind: call
      regex: '(sct|mss|grabber)\.grab$'

  # `micro-behaviors/hardware/display/screen/python::pil-imagegrab`, verbatim.
  # Stayed a text match through the migration; included as the control that
  # distinguishes "the symbol matcher broke" from "nothing fires at all".
  - id: fx-pil-imagegrab
    desc: PIL ImageGrab screen capture
    conf: 0.95
    for: [python]
    if:
      type: text
      regex: '\bImageGrab\.grab\s*\('

  # `micro-behaviors/data/source/quality/aliased-import/python::alias-subprocess`,
  # verbatim. `kind: import` + the structured `alias:` filter must fire on
  # `import subprocess as sp` but not on a plain `import subprocess` — the
  # false positive a bare `(aliased_import)` migration caused.
  - id: fx-alias-subprocess
    desc: subprocess imported under an alias
    conf: 0.6
    for: [python]
    if:
      type: symbol
      kind: import
      exact: 'subprocess'
      alias: {}

  # `micro-behaviors/data/source/syntax/keyword/python::py-keyword-xor`, the
  # `if:` half. Operator-density metric counted inline in the single AST walk.
  - id: fx-py-keyword-xor
    desc: Python bitwise XOR operator
    conf: 0.6
    for: [python]
    if:
      type: metrics
      field: 'ast.op.xor'
      min: 1

  # `objectives/anti-static/obfuscation/reflection/identity/javascript::identity-function-proxy`,
  # verbatim. The original query's `(#eq? @param @ret)` backreference is a
  # param↔return check no regex can express; the AST walker performs it and
  # exposes the count, so this pins that the counter and threshold agree.
  - id: fx-identity-function-proxy
    desc: Contains several identity wrapper functions
    conf: 0.8
    for: [javascript, typescript]
    size_max: 500000
    if:
      type: metrics
      field: 'ast.identity_function_count'
      min: 5
"#;

/// The fixture traits directory, built once per process.
fn fixture_traits_dir() -> &'static std::path::Path {
    static DIR: OnceLock<TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let td = TempDir::new().expect("create fixture traits dir");
        let dir = td.path().join("micro-behaviors/migration");
        std::fs::create_dir_all(&dir).expect("create fixture namespace dir");
        std::fs::write(dir.join("facts.yaml"), FIXTURE_TRAITS).expect("write fixture traits");
        td
    })
    .path()
}

/// Analyze `src` as a file named `name` against the fixture traits and report
/// whether any fired trait id ends with `id_suffix` (e.g. `::fx-mss-grab`).
/// The traits-dir override is process-wide, so the global lock serializes access.
fn fires(id_suffix: &str, name: &str, src: &str) -> bool {
    let _guard = crate::support::global_lock();
    cleave::traits_repo::set_override_dir(Some(fixture_traits_dir().to_path_buf()));
    let opts = cleave::AnalysisOptions::default();
    let report = cleave::analyze_bytes(src.as_bytes(), name, &opts).expect("analyze");
    cleave::traits_repo::set_override_dir(None);
    report.findings.iter().any(|f| f.id.ends_with(id_suffix))
}

/// `mss-grab` migrated from `(call (attribute attribute:(identifier) @method)
/// (#eq? @method "grab"))` to `type: symbol, kind: call` against the
/// pre-extracted call fact — and tightened to known screen-capture receivers so
/// generic `.grab()` calls no longer false-positive.
#[test]
fn mss_grab_migration_preserves_positives_and_drops_noise() {
    // Positives — real screen-capture grabs still fire.
    assert!(
        fires(
            "::fx-mss-grab",
            "cap_mss.py",
            "import mss\nwith mss.mss() as sct:\n    img = sct.grab(monitor)\n",
        ),
        "mss `sct.grab(monitor)` must still fire the call-fact matcher",
    );
    // PIL `ImageGrab.grab()` is screen capture too, but is covered by the
    // dedicated `pil-imagegrab` trait — mss-grab was tightened to the
    // remaining capture receivers (sct/mss/grabber) to stay under the
    // alternation limit, so ImageGrab is correctly NOT an mss-grab hit.
    assert!(
        fires(
            "::fx-pil-imagegrab",
            "cap_pil.py",
            "from PIL import ImageGrab\nImageGrab.grab()\n",
        ),
        "PIL `ImageGrab.grab()` must fire the text matcher",
    );

    // Negatives — the tightened rule drops generic `.grab()` noise the old
    // query flagged (queue/lock/grabber/arbitrary receivers).
    assert!(
        !fires("::fx-mss-grab", "noise1.py", "q.grab()\nlock.grab()\n"),
        "generic `.grab()` (queue/lock) must NOT fire the tightened receiver regex",
    );
    assert!(
        !fires(
            "::fx-mss-grab",
            "noise2.py",
            "x.grabber()\nresult = data.grab()\n"
        ),
        "near-misses (`.grabber()`, arbitrary `.grab()`) must NOT fire",
    );
}

/// `alias-*` traits migrated from `(aliased_import)` queries to
/// `kind: import` + the structured `alias:` filter. They must fire on an
/// aliased import (`import subprocess as sp`) but NOT on a plain import — the
/// plain import is benign and was the false-positive the bare migration caused.
#[test]
fn alias_import_traits_fire_only_on_aliased_imports() {
    assert!(
        fires(
            "::fx-alias-subprocess",
            "obf.py",
            "import subprocess as sp\nsp.run(['ls'])\n",
        ),
        "`import subprocess as sp` must fire the alias-filtered import matcher",
    );
    assert!(
        !fires(
            "::fx-alias-subprocess",
            "plain.py",
            "import subprocess\nsubprocess.run(['ls'])\n",
        ),
        "plain `import subprocess` (benign) must NOT fire the alias filter",
    );
}

/// Structural-density traits migrated from tree-sitter queries to filefacts
/// `ast.*` metrics (counted inline in the single AST walk, matched O(1) via
/// `type: metrics`): operator density (`ast.op.xor`) and the identity-proxy
/// backreference the walker checks (`ast.identity_function_count`).
#[test]
fn ast_density_metric_migrations_fire() {
    assert!(
        fires("::fx-py-keyword-xor", "x.py", "x = a ^ b\n"),
        "a `^` operator must fire the ast.op.xor metric matcher",
    );
    assert!(
        fires(
            "::fx-identity-function-proxy",
            "obf.js",
            &(0..6)
                .map(|i| format!("function f{i}(x){{ return x; }}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        "6 identity-proxy functions must fire via ast.identity_function_count",
    );
    // A function that does NOT return its own parameter must not count.
    assert!(
        !fires(
            "::fx-identity-function-proxy",
            "ok.js",
            &(0..6)
                .map(|i| format!("function f{i}(x){{ return x + 1; }}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        "non-identity functions must NOT reach the ast.identity_function_count threshold",
    );
}
