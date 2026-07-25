//! Regression test: switching the traits directory mid-process must actually
//! switch the rules that fire.
//!
//! `CapabilityMapper` is a process-wide singleton cached in `shared_resources`
//! and keyed on nothing. Before `traits_repo::set_override_dir` invalidated that
//! cache, the *first* traits directory any caller loaded won for the life of the
//! process: later overrides were accepted, the analysis still ran, and it
//! silently evaluated the wrong rule set. Nothing errored, so the only symptom
//! was findings that didn't match the traits you asked for.
//!
//! That made the integration suite order-dependent — two test modules pointing
//! at different fixture traits in one process would see whichever loaded first,
//! so the *set* of failures varied run to run and looked like load-sensitive
//! flakiness. This test pins the fix directly: same input, two traits dirs, two
//! different answers, in one process.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tempfile::TempDir;

/// Two fixture rule sets that disagree about the same input: `alpha` fires only
/// `fx-alpha`, `beta` only `fx-beta`. Any cross-contamination is unambiguous.
fn write_traits(dir: &std::path::Path, id: &str) {
    let ns = dir.join("metadata/package/manifest");
    std::fs::create_dir_all(&ns).unwrap();
    std::fs::write(
        ns.join("probe.yaml"),
        format!(
            r#"
defaults:
  platforms: [unix, windows]
  crit: notable
  conf: 0.9
traits:
  - id: {id}
    desc: Probe trait for traits-dir isolation
    for: [package.json]
    if:
      type: value
      path: name
      exists: true
"#
        ),
    )
    .unwrap();
}

const MANIFEST: &str = r#"{"name":"probe","version":"1.0.0"}"#;

fn fired_ids(traits_dir: &std::path::Path) -> Vec<String> {
    cleave::traits_repo::set_override_dir(Some(traits_dir.to_path_buf()));
    let opts = cleave::AnalysisOptions::default();
    let report =
        cleave::analyze_bytes(MANIFEST.as_bytes(), "package.json", &opts).expect("analyze");
    report.findings.iter().map(|f| f.id.clone()).collect()
}

#[test]
fn switching_traits_dir_switches_the_rules_that_fire() {
    let _guard = crate::support::global_lock();

    let alpha = TempDir::new().unwrap();
    let beta = TempDir::new().unwrap();
    write_traits(alpha.path(), "fx-alpha");
    write_traits(beta.path(), "fx-beta");

    let first = fired_ids(alpha.path());
    assert!(
        first.iter().any(|id| id.ends_with("::fx-alpha")),
        "first traits dir must be the one that fires; got {first:?}",
    );

    // The failure this pins: `second` comes back holding `fx-alpha` because the
    // mapper cached during the first analysis is still serving alpha's rules.
    let second = fired_ids(beta.path());
    cleave::traits_repo::set_override_dir(None);

    assert!(
        second.iter().any(|id| id.ends_with("::fx-beta")),
        "second traits dir must take effect; got {second:?}",
    );
    assert!(
        !second.iter().any(|id| id.ends_with("::fx-alpha")),
        "stale mapper leaked the first traits dir into the second analysis; got {second:?}",
    );
}
