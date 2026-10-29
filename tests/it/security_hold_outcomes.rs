//! A registry-held dependency is hostile on the declaring manifest only.
use cleave::{
    AnalysisOptions, Criticality,
    types::{AnalysisReport, FileAnalysis, TargetInfo},
};
use std::collections::BTreeMap;

#[test]
fn security_hold_marks_only_the_declaring_manifest_hostile() {
    let dir = tempfile::tempdir().unwrap();
    let metadata = dir.path().join("metadata/package/dependencies/declaration");
    let objectives = dir.path().join("objectives/supply-chain/security-hold");
    std::fs::create_dir_all(&metadata).unwrap();
    std::fs::create_dir_all(&objectives).unwrap();
    std::fs::write(
        metadata.join("hold.yaml"),
        r#"
defaults:
  for: [package.json]
  platforms: [unix, windows]
traits:
  - id: declared-dependency-security-held
    desc: Declared dependency has registry security hold
    crit: notable
    if: {type: metrics, field: references.security_hold_count, min: 1}
"#,
    )
    .unwrap();
    std::fs::write(
        objectives.join("hold.yaml"),
        r#"
defaults:
  for: [package.json]
  platforms: [unix, windows]
composite_rules:
  - id: declared-dependency-security-held
    desc: Declares dependency placed under security hold
    crit: hostile
    scope: file
    all:
      - id: metadata/package/dependencies/declaration::declared-dependency-security-held
"#,
    )
    .unwrap();
    cleave::traits_repo::set_override_dir(Some(dir.path().to_owned()));
    for (held, expected) in [(0.0, false), (1.0, true)] {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "package.json".into(),
            file_type: "package.json".into(),
            size_bytes: 1,
            sha256: "source".into(),
            architectures: None,
        });
        report.files = vec![
            FileAnalysis {
                id: 0,
                path: "package.json".into(),
                file_type: "package.json".into(),
                sha256: "source".into(),
                filefacts_metrics: Some(BTreeMap::from([
                    ("references.declared_count".into(), 1.0),
                    ("references.security_hold_count".into(), held),
                ])),
                ..Default::default()
            },
            FileAnalysis {
                id: 1,
                path: "other/package.json".into(),
                file_type: "package.json".into(),
                sha256: "other".into(),
                ..Default::default()
            },
        ];
        cleave::graft_reference_outcome_traits(&mut report, "source", &AnalysisOptions::default())
            .unwrap();
        let is_hostile_hold = |file: &FileAnalysis| {
            file.findings.iter().any(|f| {
                f.id.as_str()
                    == "objectives/supply-chain/security-hold::declared-dependency-security-held"
                    && f.crit == Criticality::Hostile
            })
        };
        assert_eq!(is_hostile_hold(&report.files[0]), expected);
        assert!(!is_hostile_hold(&report.files[1]));
    }
    cleave::traits_repo::set_override_dir(None);
}
