//! Regression test for the sub-100-byte structured-manifest evaluation gap.
//!
//! A tiny `package.json` carries zero extracted strings — its signal lives in
//! parsed key/value fields. The non-dependent trait pass used to short-circuit
//! on `binary_data.len() < 100 && !has_strings`, silently skipping every
//! positive `value:`/kv trait on skeleton manifests — exactly the supply-chain
//! namespace-squatting shape worth flagging. Structured manifests are now
//! exempt from that size guard (`evaluate_traits.rs`); these tests pin the
//! contract so the optimization can't quietly return and re-break it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Analyze `src` as a file named `name` against the local traits checkout and
/// return every fired trait id. Returns `None` (skip) when no traits checkout
/// is present, e.g. packaged-crate CI. The traits-dir override is process-wide,
/// so the env lock serializes access.
fn fired_ids(name: &str, src: &str) -> Option<Vec<String>> {
    let _guard = crate::support::global_lock();
    let td = crate::support::require_traits_dir()?;
    cleave::traits_repo::set_override_dir(Some(td));
    let opts = cleave::AnalysisOptions::default();
    let report = cleave::analyze_bytes(src.as_bytes(), name, &opts).expect("analyze");
    cleave::traits_repo::set_override_dir(None);
    Some(report.findings.iter().map(|f| f.id.clone()).collect())
}

/// A 46-byte `package.json` (well under the 100-byte short-circuit, zero
/// extracted strings) must still evaluate positive `value:` traits.
#[test]
fn tiny_manifest_still_evaluates_value_traits() {
    let src = r#"{"name":"x","version":"1.0.0","license":"ISC"}"#;
    assert!(src.len() < 100, "fixture must exercise the <100-byte path");

    let Some(ids) = fired_ids("package.json", src) else {
        return;
    };

    // `npm-init-default-license` is `value: license exact: ISC` — a positive
    // value match that only surfaces if the non-dependent pass runs.
    assert!(
        ids.iter()
            .any(|id| id.ends_with("::npm-init-default-license")),
        "tiny package.json must still fire positive value traits; got {ids:?}",
    );
    // `npm-has-name` is `value: name exists: true` — likewise.
    assert!(
        ids.iter().any(|id| id.ends_with("::npm-has-name")),
        "tiny package.json must fire npm-has-name; got {ids:?}",
    );
}

/// The @node-mf/utils Aikido shape: a metadata-only manifest whose license is a
/// fabricated non-SPDX freeform string. The atom and its suspicious composite
/// both depend on positive value matches firing on a sub-100-byte manifest.
#[test]
fn tiny_skeleton_with_fabricated_license_is_suspicious() {
    let src = r#"{"name":"@x/u","version":"0.0.1","license":"Trinity Optima Production"}"#;
    assert!(src.len() < 100, "fixture must exercise the <100-byte path");

    let Some(ids) = fired_ids("package.json", src) else {
        return;
    };

    assert!(
        ids.iter()
            .any(|id| id.ends_with("::manifest-freeform-license")),
        "fabricated non-SPDX license must fire manifest-freeform-license; got {ids:?}",
    );
    assert!(
        ids.iter()
            .any(|id| id.ends_with("::npm-skeleton-fabricated-license")),
        "skeleton + fabricated license must fire the suspicious composite; got {ids:?}",
    );
}

/// A legitimate package with a real SPDX license and supporting metadata must
/// NOT trip the fabricated-license heuristic — guards against false positives.
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
        let Some(ids) = fired_ids("package.json", &src) else {
            return;
        };
        assert!(
            !ids.iter()
                .any(|id| id.ends_with("::manifest-freeform-license")),
            "license {license:?} must not fire manifest-freeform-license; got {ids:?}",
        );
        assert!(
            !ids.iter()
                .any(|id| id.ends_with("::npm-skeleton-fabricated-license")),
            "license {license:?} must not fire the suspicious composite; got {ids:?}",
        );
    }
}

/// The freeform-license notable is cross-ecosystem: composer.json (shares the
/// top-level `license` key with npm), Cargo.toml (`package.license`), and
/// pyproject.toml (`project.license`) each surface their own variant.
#[test]
fn freeform_license_fires_across_ecosystems() {
    let cases = [
        (
            "composer.json",
            r#"{"name":"x/y","license":"Acme Closed Source"}"#,
            "::manifest-freeform-license",
        ),
        (
            "Cargo.toml",
            "[package]\nname=\"x\"\nversion=\"0.1.0\"\nlicense=\"Trinity Optima Production\"\n",
            "::cargo-freeform-license",
        ),
        (
            "pyproject.toml",
            "[project]\nname=\"x\"\nlicense=\"Trinity Optima Production\"\n",
            "::pyproject-freeform-license",
        ),
    ];
    for (name, src, suffix) in cases {
        let Some(ids) = fired_ids(name, src) else {
            return;
        };
        assert!(
            ids.iter().any(|id| id.ends_with(suffix)),
            "{name} freeform license must fire {suffix}; got {ids:?}",
        );
    }
}
