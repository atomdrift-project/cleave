//! Regression test for the sub-100-byte structured-manifest evaluation gap.
//!
//! A tiny `package.json` carries zero extracted strings — its signal lives in
//! parsed key/value fields. The non-dependent trait pass used to short-circuit
//! on `binary_data.len() < 100 && !has_strings`, silently skipping every
//! positive `value:`/kv trait on skeleton manifests — exactly the supply-chain
//! namespace-squatting shape worth flagging. Structured manifests are now
//! exempt from that size guard (`evaluate_traits.rs`); these tests pin the
//! contract so the optimization can't quietly return and re-break it.
//!
//! The claim under test is about cleave's evaluator, not about any particular
//! rule, so the traits below are a self-contained fixture written to a temp dir
//! — not the sibling traits checkout. Tying these to an external repo made them
//! fail for two unrelated reasons (evaluator broke / a trait got renamed) and,
//! worse, silently skip when the checkout was absent. Each fixture trait mirrors
//! the *shape* of the real trait named in its comment; keeping them in-tree is
//! what makes the suite hermetic and the failures unambiguous.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::OnceLock;
use tempfile::TempDir;

/// Minimal trait set exercising each `value:` matcher the size-guard exemption
/// has to keep alive: `exact:`, `exists:`, and `regex:` narrowed by `unless:`,
/// plus a composite built on two of them.
const FIXTURE_TRAITS: &str = r#"
defaults:
  platforms: [unix, windows]
  crit: notable
  conf: 0.9

traits:
  # Shape of `objectives/supply-chain/impersonation/manifest/placeholder::npm-init-default-license`:
  # a positive `value: exact:` match, which only surfaces if the non-dependent
  # pass runs on a sub-100-byte manifest.
  - id: fx-license-isc
    desc: Manifest declares the npm-init default ISC license
    crit: baseline
    conf: 0.95
    for: [package.json]
    if:
      type: value
      path: license
      exact: ISC

  # Shape of `metadata/package/quality/empty::npm-has-name` — positive
  # `value: exists:` match.
  - id: fx-has-name
    desc: Manifest defines a package name
    crit: baseline
    conf: 1.0
    for: [package.json]
    if:
      type: value
      path: name
      exists: true

  # Shape of `metadata/package/license::manifest-freeform-license`. The `if:`
  # regex is deliberately broad and every bit of precision lives in `unless:`,
  # so this pins that negative clauses are evaluated alongside positives on a
  # tiny manifest — the half most likely to be dropped by a size short-circuit.
  - id: fx-freeform-license
    desc: Package license is a non-SPDX freeform string
    conf: 0.65
    for: [package.json, composer.json]
    if:
      type: value
      path: license
      regex: '^[A-Za-z]+ [A-Za-z]+( [A-Za-z]+)*$'
    unless:
      - type: value
        path: license
        regex: '^SEE LICENSE IN '
      - type: value
        path: license
        regex: '(?i)licen[sc]e'
      - type: value
        path: license
        regex: '(?i)(public domain|creative commons|all rights reserved)'
      - type: value
        path: license
        regex: '(?i)\b(gnu|gpl|lgpl|agpl)\b'
      - type: value
        path: license
        regex: '(?i)\b(mit|bsd|apache|mpl)\b'

  # Same rule against a nested TOML path (`package.license`), which reaches the
  # value tree through a different parser than the JSON manifests above.
  - id: fx-cargo-freeform-license
    desc: Cargo license is a non-SPDX freeform string
    conf: 0.65
    for: [cargo.toml]
    if:
      type: value
      path: package.license
      regex: '^[A-Za-z]+ [A-Za-z]+( [A-Za-z]+)*$'
    unless:
      - type: value
        path: package.license
        regex: '(?i)licen[sc]e'
      - type: value
        path: package.license
        regex: '(?i)\b(mit|bsd|apache|mpl)\b'

  - id: fx-pyproject-freeform-license
    desc: pyproject license is a non-SPDX freeform string
    conf: 0.65
    for: [pyproject.toml]
    if:
      type: value
      path: project.license
      regex: '^[A-Za-z]+ [A-Za-z]+( [A-Za-z]+)*$'
    unless:
      - type: value
        path: project.license
        regex: '(?i)licen[sc]e'
      - type: value
        path: project.license
        regex: '(?i)\b(mit|bsd|apache|mpl)\b'

composite_rules:
  # Shape of `metadata/package/quality/empty::npm-skeleton-fabricated-license`:
  # a composite whose legs are both `value:` traits, so it only fires if the
  # tiny manifest reached composite evaluation with those legs present.
  - id: fx-skeleton-fabricated-license
    desc: Metadata-only package with a fabricated non-SPDX license
    crit: suspicious
    conf: 0.85
    for: [package.json]
    all:
      - id: fx-has-name
      - id: fx-freeform-license
"#;

/// The fixture traits directory, built once per process.
///
/// Shared rather than per-test so the trait loader's cache stays warm; the
/// `TempDir` lives for the process and is cleaned up on exit.
fn fixture_traits_dir() -> &'static std::path::Path {
    static DIR: OnceLock<TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let td = TempDir::new().expect("create fixture traits dir");
        // Nested under `metadata/` so the loader sees a plausible traits layout
        // and the ids acquire a `<namespace>::` prefix, as real traits do.
        let dir = td.path().join("metadata/package/manifest");
        std::fs::create_dir_all(&dir).expect("create fixture namespace dir");
        std::fs::write(dir.join("tiny.yaml"), FIXTURE_TRAITS).expect("write fixture traits");
        td
    })
    .path()
}

/// Analyze `src` as a file named `name` against the fixture traits and return
/// every fired trait id. The traits-dir override is process-wide, so the global
/// lock serializes access.
fn fired_ids(name: &str, src: &str) -> Vec<String> {
    let _guard = crate::support::global_lock();
    cleave::traits_repo::set_override_dir(Some(fixture_traits_dir().to_path_buf()));
    let opts = cleave::AnalysisOptions::default();
    let report = cleave::analyze_bytes(src.as_bytes(), name, &opts).expect("analyze");
    cleave::traits_repo::set_override_dir(None);
    report.findings.iter().map(|f| f.id.to_string()).collect()
}

/// A 46-byte `package.json` (well under the 100-byte short-circuit, zero
/// extracted strings) must still evaluate positive `value:` traits.
#[test]
fn tiny_manifest_still_evaluates_value_traits() {
    let src = r#"{"name":"x","version":"1.0.0","license":"ISC"}"#;
    assert!(src.len() < 100, "fixture must exercise the <100-byte path");

    let ids = fired_ids("package.json", src);

    // `value: license exact: ISC` — a positive value match that only surfaces
    // if the non-dependent pass runs.
    assert!(
        ids.iter().any(|id| id.ends_with("::fx-license-isc")),
        "tiny package.json must still fire positive value traits; got {ids:?}",
    );
    // `value: name exists: true` — likewise.
    assert!(
        ids.iter().any(|id| id.ends_with("::fx-has-name")),
        "tiny package.json must fire fx-has-name; got {ids:?}",
    );
}

/// The @node-mf/utils Aikido shape: a metadata-only manifest whose license is a
/// fabricated non-SPDX freeform string. The trait and the composite above it
/// both depend on positive value matches firing on a sub-100-byte manifest.
#[test]
fn tiny_skeleton_with_fabricated_license_is_suspicious() {
    let src = r#"{"name":"@x/u","version":"0.0.1","license":"Trinity Optima Production"}"#;
    assert!(src.len() < 100, "fixture must exercise the <100-byte path");

    let ids = fired_ids("package.json", src);

    assert!(
        ids.iter().any(|id| id.ends_with("::fx-freeform-license")),
        "fabricated non-SPDX license must fire fx-freeform-license; got {ids:?}",
    );
    assert!(
        ids.iter()
            .any(|id| id.ends_with("::fx-skeleton-fabricated-license")),
        "skeleton + fabricated license must fire the suspicious composite; got {ids:?}",
    );
}

/// A legitimate package with a real SPDX license and supporting metadata must
/// NOT trip the fabricated-license heuristic — this is the `unless:` half of
/// the contract, which a size short-circuit would also silently drop.
/// `"BSD License"` is the trap: it is multi-word and non-SPDX, but the
/// recognised-token exclusion must keep it from firing.
#[test]
fn normal_package_does_not_trip_fabricated_license() {
    for license in [
        "MIT",
        "Apache-2.0",
        "BSD License",
        "GNU General Public License v3",
    ] {
        let src = format!(
            r#"{{"name":"left-pad","version":"1.3.0","license":"{license}","repository":"github:x/left-pad","keywords":["pad"]}}"#
        );
        let ids = fired_ids("package.json", &src);
        assert!(
            !ids.iter().any(|id| id.ends_with("::fx-freeform-license")),
            "license {license:?} must not fire fx-freeform-license; got {ids:?}",
        );
        assert!(
            !ids.iter()
                .any(|id| id.ends_with("::fx-skeleton-fabricated-license")),
            "license {license:?} must not fire the suspicious composite; got {ids:?}",
        );
    }
}

/// Value traits are cross-ecosystem: composer.json (shares the top-level
/// `license` key with npm), Cargo.toml (`package.license`), and pyproject.toml
/// (`project.license`) each reach the value tree through their own parser, so
/// the exemption has to hold for all of them, not just package.json.
#[test]
fn freeform_license_fires_across_ecosystems() {
    let cases = [
        (
            "composer.json",
            r#"{"name":"x/y","license":"Acme Closed Source"}"#,
            "::fx-freeform-license",
        ),
        (
            "Cargo.toml",
            "[package]\nname=\"x\"\nversion=\"0.1.0\"\nlicense=\"Trinity Optima Production\"\n",
            "::fx-cargo-freeform-license",
        ),
        (
            "pyproject.toml",
            "[project]\nname=\"x\"\nlicense=\"Trinity Optima Production\"\n",
            "::fx-pyproject-freeform-license",
        ),
    ];
    for (name, src, suffix) in cases {
        let ids = fired_ids(name, src);
        assert!(
            ids.iter().any(|id| id.ends_with(suffix)),
            "{name} freeform license must fire {suffix}; got {ids:?}",
        );
    }
}
