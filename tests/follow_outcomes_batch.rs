//! Follow facts must keep source attribution while shared containers are pooled once.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use cleave::{
    AnalysisOptions,
    types::{AnalysisReport, FileAnalysis, Finding, TargetInfo},
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn batched_follow_matches_sequential_local_and_container_findings() {
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
    scope: archive
    desc: Startup and missing command in archive
    all: [{id: local}, {id: startup}]
"#,
    )
    .unwrap();
    cleave::traits_repo::set_override_dir(Some(dir.path().to_owned()));
    let id = |name: &str| format!("micro-behaviors/process/create/task::{name}");
    for source_count in [6, 96] {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "sample.vsix".into(),
            file_type: "vsix".into(),
            size_bytes: 1,
            sha256: "root".into(),
            architectures: None,
        });
        for (path, sha, depth, startup) in [
            ("sample.vsix", "root", 0, true),
            ("sample.vsix!!nested.vsix", "nested", 1, true),
            ("other.vsix", "unrelated", 0, false),
        ] {
            report.files.push(FileAnalysis {
                id: u32::try_from(report.files.len()).unwrap(),
                path: path.into(),
                sha256: sha.into(),
                depth,
                file_type: "vsix".into(),
                findings: if startup {
                    vec![Finding::capability(id("startup"), "startup".into(), 1.0)]
                } else {
                    vec![]
                },
                ..Default::default()
            });
        }
        let mut sources = Vec::new();
        for n in 0..source_count {
            let parent = match n % 3 {
                0 => "sample.vsix",
                1 => "sample.vsix!!nested.vsix",
                _ => "other.vsix",
            };
            let sha = format!("source-{n}");
            let mut command = Finding::capability(id("command"), "command".into(), 1.0);
            command.precomputed_spans = Some(vec![[100, 20]]);
            report.files.push(FileAnalysis {
                id: u32::try_from(report.files.len()).unwrap(),
                path: format!("{parent}!!{n}.js"),
                sha256: sha.clone(),
                depth: if n % 3 == 1 { 2 } else { 1 },
                file_type: "javascript".into(),
                findings: vec![command],
                filefacts_metrics: Some(BTreeMap::from([
                    ("references.declared_count".into(), 1.0),
                    ("references.unavailable_command_count".into(), 1.0),
                ])),
                ..Default::default()
            });
            sources.push((
                sha,
                BTreeMap::from([(
                    "references.unavailable_command_count".into(),
                    vec![filefacts::Span::new(if n % 2 == 0 { 100 } else { 900 }, 1)],
                )]),
            ));
        }
        let options = AnalysisOptions::default();
        let mut sequential = report.clone();
        for (sha, spans) in &sources {
            cleave::graft_located_reference_outcome_traits(&mut sequential, sha, &options, spans)
                .unwrap();
        }
        let signatures = |r: &AnalysisReport| -> BTreeMap<String, BTreeSet<String>> {
            r.files
                .iter()
                .map(|f| {
                    (
                        f.path.clone(),
                        f.findings.iter().map(|v| v.id.to_string()).collect(),
                    )
                })
                .collect()
        };
        for reverse in [false, true] {
            let mut batched = report.clone();
            let mut refs: Vec<_> = sources
                .iter()
                .map(|(sha, spans)| (sha.as_str(), spans))
                .collect();
            if reverse {
                refs.reverse();
            }
            cleave::graft_reference_outcomes_batch(&mut batched, &refs, &options).unwrap();
            assert_eq!(signatures(&batched), signatures(&sequential));
            assert_eq!(
                serde_json::to_value(&batched.summary).unwrap(),
                serde_json::to_value(&sequential.summary).unwrap()
            );
            if source_count == 6 {
                for (actual, expected) in batched.files.iter().zip(&sequential.files) {
                    assert_eq!(
                        serde_json::to_value(&actual.composite_sources).unwrap(),
                        serde_json::to_value(&expected.composite_sources).unwrap(),
                        "{}",
                        actual.path
                    );
                }
            }

            for n in 0..source_count {
                let file = &batched.files[3 + n];
                assert_eq!(
                    file.findings.iter().any(|f| f.id.as_str() == id("local")),
                    n % 2 == 0
                );
            }
            assert!(
                batched.files[0]
                    .findings
                    .iter()
                    .any(|f| f.id.as_str() == id("archive"))
            );
            assert!(
                batched.files[1]
                    .findings
                    .iter()
                    .any(|f| f.id.as_str() == id("archive"))
            );
            assert!(
                !batched.files[2]
                    .findings
                    .iter()
                    .any(|f| f.id.as_str() == id("archive"))
            );
        }
    }
    cleave::traits_repo::set_override_dir(None);
}
