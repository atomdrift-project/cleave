//! Post-fetch facts must retain source locality through archive retention.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cleave::{
    AnalysisOptions,
    types::{AnalysisReport, FileAnalysis, Finding, TargetInfo},
};
use std::collections::BTreeMap;

#[test]
fn located_follow_facts_recheck_local_and_immediate_archive_rules() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("micro-behaviors/process/create/task");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("test.yaml"),
        r#"
defaults:
  for: [javascript, package.json, vsix]
  platforms: [unix, windows]
  crit: notable
  conf: 1.0
traits:
  - id: command
    desc: Command marker
    if: {type: raw, exact: command}
  - id: startup
    desc: Startup marker
    if: {type: raw, exact: startup}
  - id: absent
    desc: Absent commanded package
    if: {type: metrics, field: references.unavailable_command_count, min: 1}
composite_rules:
  - id: local
    scope: file
    desc: Missing command at matching location
    near_bytes: 0
    all: [{id: command}, {id: absent}]
  - id: archive
    desc: Startup and missing command in archive
    scope: archive
    all: [{id: local}, {id: startup}]
"#,
    )
    .unwrap();
    cleave::traits_repo::set_override_dir(Some(dir.path().to_owned()));
    let id = |name: &str| format!("micro-behaviors/process/create/task::{name}");
    let finding = |name: &str| Finding::capability(id(name), name.to_owned(), 1.0);
    for (offset, startup_parent, count, want_local, want_archive) in [
        (100, "sample.vsix", 1.0, true, true),
        (900, "sample.vsix", 1.0, false, false),
        (100, "other.vsix", 1.0, true, false),
        (100, "sample.vsix", 0.0, false, false),
    ] {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "sample.vsix".into(),
            file_type: "vsix".into(),
            size_bytes: 1,
            sha256: "root".into(),
            architectures: None,
        });
        let mut command = finding("command");
        command.precomputed_spans = Some(vec![[100, 20]]);
        report.files = vec![
            FileAnalysis {
                id: 0,
                path: "sample.vsix".into(),
                file_type: "vsix".into(),
                sha256: "root".into(),
                ..Default::default()
            },
            FileAnalysis {
                id: 1,
                path: "sample.vsix!!main.js".into(),
                file_type: "javascript".into(),
                sha256: "source".into(),
                depth: 1,
                findings: vec![command],
                filefacts_metrics: Some(BTreeMap::from([
                    ("references.declared_count".into(), 1.0),
                    ("references.unavailable_command_count".into(), count),
                ])),
                ..Default::default()
            },
            FileAnalysis {
                id: 2,
                path: format!("{startup_parent}!!package.json"),
                file_type: "package.json".into(),
                sha256: "manifest".into(),
                depth: 1,
                findings: vec![finding("startup")],
                ..Default::default()
            },
        ];
        let spans = BTreeMap::from([(
            "references.unavailable_command_count".into(),
            vec![filefacts::Span::new(offset, 1)],
        )]);
        cleave::graft_located_reference_outcome_traits(
            &mut report,
            "source",
            &AnalysisOptions::default(),
            &spans,
        )
        .unwrap();
        assert_eq!(
            report.files[1]
                .findings
                .iter()
                .any(|f| f.id.as_str() == id("local")),
            want_local,
            "offset={offset}, count={count}, findings={:?}",
            report.files[1].findings
        );
        assert_eq!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id.as_str() == id("archive")),
            want_archive,
            "offset={offset}, parent={startup_parent}, count={count}"
        );
    }
    cleave::traits_repo::set_override_dir(None);
}
