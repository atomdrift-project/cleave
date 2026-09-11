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
  # metadata/file/encoded::gzip-base64-like-literal. Validate the whole
  # parsed string, not an arbitrary Base64-looking substring in source text.
  - id: fx-gzip-base64-literal
    desc: Base64-compatible literal with gzip prefix
    for: [javascript, typescript]
    if:
      type: literal
      kind: string
      regex: '^H4sIA[A-Za-z0-9+/]{192,}={0,2}$'
      is: base64

  # Bind the computed key and module call to the SAME declaration. Byte
  # proximity to an unrelated import cannot establish this relationship.
  - id: fx-computed-child-process-binding
    desc: Computed child_process member binding
    for: [javascript, typescript]
    if:
      type: tree-sitter
      language: javascript
      query: |
        (variable_declarator
          name: (object_pattern
            (pair_pattern key: (computed_property_name))) @pattern
          value: (call_expression
            function: (identifier) @fn
            arguments: (arguments (string) @module))
          (#eq? @fn "require")
          (#match? @module "^['\"](node:)?child_process['\"]$"))

  # Matcher contract for metadata/file/encoded::require-expression-text.
  # No intent or decoded-language claim: `for` constrains the carrier only.
  - id: fx-encoded-require-text
    desc: Encoded text contains require expression
    crit: notable
    for: [javascript, typescript]
    if:
      type: encoded
      encoding: [base64, base64-obf, hex, base32, base85, xor, stack]
      regex: '\brequire\s*\('

  - id: fx-host-require-call
    desc: Source calls require
    for: [javascript, typescript]
    if:
      type: symbol
      kind: call
      exact: require

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

// The production metadata/file/profile/metrics::numeric-suffix-identifiers
// count/size matcher, isolated from checkout-dependent context exclusions.
const IDENTIFIER_METRIC_TRAIT: &str = r#"
traits:
  - id: fx-numeric-suffix-identifiers
    desc: At least 100 numeric-suffixed identifier names
    crit: notable
    conf: 0.75
    for: [scripts, pe, elf, macho]
    platforms: [windows, unix]
    size_min: 15001
    if:
      type: metrics
      field: identifiers.numeric_suffix_count
      min: 100
      min_size: 15001
"#;

// File creation can set execute bits without a subsequent chmod. A nested
// data-producing call and a conditional mode must not hide that observation.
const EXECUTABLE_WRITE_TRAITS: &str = r#"
defaults:
  for: [javascript, typescript]
  platforms: [unix, windows]
  crit: notable
traits:
  - id: fx-write-call
    desc: Calls synchronous file write
    if:
      type: symbol
      kind: call
      regex: '(^|\.)writeFileSync$'
  - id: fx-write-mode
    desc: Writes with executable mode
    if:
      type: text
      regex: 'writeFile(Sync)?.{0,300}\bmode\s*:.{0,100}\b0o755\b'
composite_rules:
  - id: fx-executable-write
    desc: Calls write with executable mode evidence
    all:
      - id: fx-write-call
      - id: fx-write-mode
    near_bytes: 2048
"#;

/// The fixture traits directory, built once per process.
fn fixture_traits_dir() -> &'static std::path::Path {
    static DIR: OnceLock<TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let td = TempDir::new().expect("create fixture traits dir");
        let dir = td.path().join("micro-behaviors/migration");
        std::fs::create_dir_all(&dir).expect("create fixture namespace dir");
        std::fs::write(dir.join("facts.yaml"), FIXTURE_TRAITS).expect("write fixture traits");
        std::fs::write(dir.join("executable-write.yaml"), EXECUTABLE_WRITE_TRAITS)
            .expect("write executable creation fixture");
        let metrics = td.path().join("metadata/file/profile/metrics");
        std::fs::create_dir_all(&metrics).expect("create metadata namespace");
        std::fs::write(metrics.join("identifiers.yaml"), IDENTIFIER_METRIC_TRAIT)
            .expect("write identifier metric trait");
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

#[test]
fn executable_creation_mode_survives_nested_data_and_conditional_mode() {
    for source in [
        "import { writeFileSync } from 'fs'; writeFileSync(dst, inflate(data), {mode: win ? 0o644 : 0o755});",
        "const fs = require('fs'); fs.writeFileSync(dst, data, {mode: 0o755});",
    ] {
        assert!(fires("::fx-executable-write", "writer.js", source));
    }
    for source in [
        "import { writeFileSync } from 'fs'; writeFileSync(dst, inflate(data), {mode: 0o644});",
        "import { writeFileSync } from 'fs'; writeFileSync(dst, data);",
        "const documentation = 'writeFileSync(dst, data, {mode: 0o755})';",
    ] {
        assert!(!fires("::fx-executable-write", "writer.js", source));
    }
}

#[test]
fn gzip_literal_requires_canonical_whole_string_not_source_mentions() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::io::Write;

    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&(0..=255).collect::<Vec<u8>>()).unwrap();
    let encoded = STANDARD.encode(gzip.finish().unwrap());
    assert!(encoded.starts_with("H4sIA") && encoded.len() >= 200);
    // Embedded worker bundles exceed the short-string display/extraction
    // limits. Validation must inspect full literal bytes, not a preview.
    let mut large = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::none());
    large
        .write_all(&(0..=255).cycle().take(100_000).collect::<Vec<u8>>())
        .unwrap();
    let large_encoded = STANDARD.encode(large.finish().unwrap());
    assert!(fires(
        "::fx-gzip-base64-literal",
        "large-worker.js",
        &format!("module.exports = {large_encoded:?};")
    ));
    for name in ["worker.js", "worker.ts"] {
        assert!(fires(
            "::fx-gzip-base64-literal",
            name,
            &format!("module.exports = {encoded:?};")
        ));
        assert!(fires(
            "::fx-gzip-base64-literal",
            name,
            &format!("// __wbindgen_placeholder__\nmodule.exports = {encoded:?};")
        ));
    }
    for value in [
        format!("prefix{encoded}"),
        format!("{encoded}suffix"),
        // Both pass the regex alphabet/length check, but not Base64 validation.
        format!("H4sIA{}", "A".repeat(196)), // length 1 modulo 4
        format!("H4sIA{}B==", "A".repeat(192)), // nonzero unused trailing bits
        format!("H4sIA{}=A", "A".repeat(192)), // interior padding
    ] {
        assert!(
            !fires(
                "::fx-gzip-base64-literal",
                "worker.js",
                &format!("module.exports = {value:?};")
            ),
            "{value}"
        );
    }
    assert!(!fires(
        "::fx-gzip-base64-literal",
        "worker.js",
        &format!("// {encoded}\nmodule.exports = 1;")
    ));
}

#[test]
fn numeric_suffix_metric_counts_unique_code_names_at_size_boundary() {
    let source = |count: usize, size: usize| {
        let mut src = (0..count)
            .map(|i| format!("let item{i} = 0;\n"))
            .collect::<String>();
        src.push_str("/*");
        src.extend(std::iter::repeat_n(' ', size - src.len() - 2));
        src.push_str("*/");
        assert_eq!(src.len(), size);
        src
    };
    for (count, size, expected) in [(99, 15001, false), (100, 15000, false), (100, 15001, true)] {
        assert_eq!(
            fires(
                "::fx-numeric-suffix-identifiers",
                "bundle.js",
                &source(count, size)
            ),
            expected,
            "{count} identifiers in {size} bytes",
        );
    }
    let mentions = (0..120).map(|i| format!("item{i} ")).collect::<String>();
    for src in [
        format!("/*{mentions}*/\n{}", source(0, 15001)),
        format!("const names = {mentions:?};\n{}", source(0, 15001)),
        format!("{}\n{}", "item1++;\n".repeat(120), source(0, 15001)),
    ] {
        assert!(!fires("::fx-numeric-suffix-identifiers", "bundle.js", &src));
    }
}

/// Decoded text is not a call-site fact in the carrier's source language.
/// Small in-memory sources exercise parsing and decoding without corpus scans.
#[test]
fn encoded_require_text_migration_preserves_language_neutral_evidence() {
    use base64::{Engine, engine::general_purpose::STANDARD};

    for payload in [
        "local db = require('storage')\nlocal function read(key) return db.get(key) end\n",
        "const db = require('storage'); function read(key) { return db.get(key); }",
        "Documentation: require('storage') is an example, not a call in this carrier.",
    ] {
        let carrier = format!("export default {:?};", STANDARD.encode(payload));
        assert!(
            fires("::fx-encoded-require-text", "carrier.js", &carrier),
            "decoded require text must remain observable: {payload}",
        );
    }

    let lua = "local db = require('storage')\nlocal function read(key) return db.get(key) end\n";
    let carrier = format!("export default {:?};", STANDARD.encode(lua));
    assert!(
        !fires("::fx-host-require-call", "carrier.js", &carrier),
        "Lua require text must not become a JavaScript carrier call",
    );
    assert!(fires(
        "::fx-host-require-call",
        "loader.js",
        "const db = require('storage'); db.get('key');",
    ));

    for payload in [
        "const db = prerequire('storage'); function read(key) { return db.get(key); }",
        "const db = _require('storage'); function read(key) { return db.get(key); }",
    ] {
        let carrier = format!("export default {:?};", STANDARD.encode(payload));
        assert!(!fires("::fx-encoded-require-text", "carrier.js", &carrier));
    }
}

#[test]
fn computed_child_process_binding_requires_the_same_declaration() {
    for source in [
        "const { [method]: run } = require('child_process');",
        "const { [table[0x12]]: run } = require('node:child_process');",
        "const { [decode(12)]: run } = require(\"child_process\");",
    ] {
        assert!(fires(
            "::fx-computed-child-process-binding",
            "loader.js",
            source
        ));
    }
    for source in [
        // The UiPath/open platform-selector shape: nearby unrelated import.
        "import cp from 'node:child_process'; function select(binary) { const { [arch]: archBinary } = binary; return archBinary; }",
        "const cp = require('child_process'); const { [arch]: value } = binary;",
        "const { exec: run = fallback[0] } = require('child_process');",
        "const { [method]: run } = require('not_child_process');",
        "const { [method]: run } = other('child_process');",
        "// const { [method]: run } = require('child_process');\nexport default 1;",
    ] {
        assert!(
            !fires("::fx-computed-child-process-binding", "selector.js", source),
            "{source}"
        );
    }
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
