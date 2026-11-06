use super::{
    AnalysisReport, NeutralStage, Path, TESTDATA, neutral_relative_path, path_leaks, relabel_paths,
};

fn report_at(path: &str, basename: &str) -> AnalysisReport {
    let mut report = AnalysisReport::new(cleave::TargetInfo {
        path: path.to_string(),
        file_type: "javascript".to_string(),
        size_bytes: 1,
        sha256: "abc".to_string(),
        architectures: None,
    });
    report.values_tree = Some(Box::new(serde_json::json!({
        "file": { "basename": basename, "size": 1 },
    })));
    report
}

fn forbidden(traits_dir: &str) -> Vec<String> {
    vec![TESTDATA.to_string(), traits_dir.to_lowercase()]
}

#[test]
fn neutral_path_is_content_hash_and_basename_only() {
    let fixture = Path::new("/r/traits/testdata/benign/gh-controls/.github/action.yml");
    let rel = neutral_relative_path(fixture, b"on: push\n").unwrap();
    let parts: Vec<_> = rel.iter().map(|c| c.to_str().unwrap()).collect();
    assert_eq!(parts.len(), 2, "{rel:?}");
    assert_eq!(parts[0].len(), 16);
    assert!(parts[0].bytes().all(|b| b.is_ascii_hexdigit() || b == b'g'));
    assert!(!parts[0].contains("e2e"));
    assert_eq!(parts[1], "action.yml");
    for dir in [
        "testdata",
        "benign",
        "gh-controls",
        ".github",
        "traits",
        "/r",
    ] {
        assert!(!rel.to_str().unwrap().contains(dir), "{rel:?} names {dir}");
    }
    // Same bytes share a directory; different bytes never do.
    assert_eq!(
        rel,
        neutral_relative_path(Path::new("elsewhere/action.yml"), b"on: push\n").unwrap()
    );
    assert_ne!(
        rel,
        neutral_relative_path(fixture, b"on: pull_request\n").unwrap()
    );
}

#[test]
fn neutral_stage_rejects_random_test_directory_markers() {
    assert!(super::neutral_test_path(Path::new("/tmp/cleave-validate-qa1")).unwrap());
    assert!(super::neutral_test_path(Path::new("/tmp/cleave-validate-e2e")).unwrap());
    assert!(!super::neutral_test_path(Path::new("/tmp/cleave-validate-clean")).unwrap());
}

#[test]
fn digest_stage_directory_cannot_be_an_e2e_path() {
    use sha2::{Digest, Sha256};
    let data = (0u32..100_000)
        .map(u32::to_le_bytes)
        .find(|b| hex::encode(&Sha256::digest(b)[..8]).contains("e2e"))
        .unwrap();
    let rel = neutral_relative_path(Path::new("fixture.py"), &data).unwrap();
    assert!(!super::neutral_test_path(&rel).unwrap());
    assert!(!rel.to_string_lossy().contains("e2e"));
}

#[test]
fn stage_places_fixture_outside_traits_dir_and_cleans_up() {
    let traits = tempfile::tempdir().unwrap();
    let dir = traits
        .path()
        .join("testdata")
        .join("benign")
        .join("npm-pkg");
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = dir.join("package.json");
    std::fs::write(&fixture, br#"{"name":"x"}"#).unwrap();

    let stage = NeutralStage::new(traits.path()).unwrap();
    let root = stage.dir.path().to_path_buf();
    let neutral = stage.stage(&fixture).unwrap();
    // Staging the same fixture twice (two lanes) is harmless.
    assert_eq!(neutral, stage.stage(&fixture).unwrap());

    assert!(neutral.starts_with(&root));
    assert_eq!(neutral.file_name().unwrap(), "package.json");
    assert_eq!(std::fs::read(&neutral).unwrap(), br#"{"name":"x"}"#);
    let shown = neutral.to_string_lossy().to_lowercase();
    let canonical = std::fs::canonicalize(traits.path()).unwrap();
    for bad in [
        TESTDATA.to_string(),
        "npm-pkg".to_string(),
        "benign".to_string(),
        canonical.to_string_lossy().to_lowercase(),
        traits.path().to_string_lossy().to_lowercase(),
    ] {
        assert!(!shown.contains(&bad), "{shown} contains {bad}");
    }

    drop(stage);
    assert!(!root.exists(), "stage directory must be removed");
    assert!(fixture.exists(), "the fixture itself must survive");
}

#[test]
fn analyze_removes_staged_copy_after_its_last_user() {
    let traits = tempfile::tempdir().unwrap();
    let dir = traits.path().join("testdata").join("benign");
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = dir.join("index.js");
    std::fs::write(&fixture, b"1").unwrap();
    let stage = NeutralStage::new(traits.path()).unwrap();

    // Another lane holds the same content while this one analyzes it.
    let held = stage.stage(&fixture).unwrap();
    let mut analyzed = None;
    stage
        .analyze(&fixture, |p| {
            analyzed = Some(p.to_path_buf());
            Ok(report_at(&p.to_string_lossy(), "index.js"))
        })
        .unwrap();
    assert_eq!(analyzed.as_deref(), Some(held.as_path()));
    assert!(held.exists(), "a staged copy in use must survive");

    stage.release(&held);
    assert!(!held.exists(), "the last user removes the staged copy");
    assert!(!held.parent().unwrap().exists());
    assert!(fixture.exists(), "the fixture itself must survive");
}

#[test]
fn analyze_reports_under_fixture_path_and_rejects_leaks() {
    let traits = tempfile::tempdir().unwrap();
    let dir = traits.path().join("testdata").join("benign");
    std::fs::create_dir_all(&dir).unwrap();
    let fixture = dir.join("index.js");
    std::fs::write(&fixture, b"1").unwrap();
    let stage = NeutralStage::new(traits.path()).unwrap();

    let report = stage
        .analyze(&fixture, |p| {
            Ok(report_at(&p.to_string_lossy(), "index.js"))
        })
        .unwrap();
    let original = fixture.to_string_lossy();
    assert_eq!(report.files[0].path, original);

    let neutral = stage.stage(&fixture).unwrap();
    let mut issues = vec![crate::validation_controls::ValidationIssue::new(
        "rule-performance",
        format!("cost exceeded on '{}!!/member.js'", neutral.display()),
    )];
    stage.relabel_issues(&mut issues);
    assert_eq!(
        issues[0].message,
        format!("cost exceeded on '{original}!!/member.js'")
    );

    // An engine path that bypasses the stage must fail loudly.
    let err = stage
        .analyze(&fixture, |_| Ok(report_at(&original, "index.js")))
        .unwrap_err();
    assert!(err.to_string().contains("testdata"), "{err:#}");
}

#[test]
fn guard_flags_every_path_derived_value() {
    let traits = "/Users/x/traits-dev";
    let clean = "/tmp/cleave-validate-a/0123456789abcdef/index.js";

    let mut ok = report_at(clean, "index.js");
    ok.finalize();
    assert!(path_leaks(&ok, &forbidden(traits)).is_empty());

    let mut in_testdata = report_at("/w/TestData/benign/index.js", "index.js");
    in_testdata.finalize();
    assert!(!path_leaks(&in_testdata, &forbidden(traits)).is_empty());

    let mut in_traits = report_at(&format!("{traits}/benign/index.js"), "index.js");
    in_traits.finalize();
    assert!(!path_leaks(&in_traits, &forbidden(traits)).is_empty());

    // A basename is path-derived even when the path is clean.
    let mut basename = report_at(clean, "testdata-index.js");
    basename.finalize();
    let leaks = path_leaks(&basename, &forbidden(traits));
    assert!(
        leaks.iter().any(|l| l.starts_with("file.basename")),
        "{leaks:?}"
    );

    // Only the flattened kv (e.g. restored from cache) carries it.
    let mut kv_only = report_at(clean, "index.js");
    kv_only.finalize();
    kv_only.values_tree = None;
    kv_only.files[0]
        .kv
        .insert("file.stem".into(), serde_json::json!("testdata"));
    assert!(!path_leaks(&kv_only, &forbidden(traits)).is_empty());

    // A member file whose host path escaped the stage.
    let mut member = report_at(clean, "index.js");
    member.finalize();
    let mut escaped = member.files[0].clone();
    escaped.path = format!("{traits}/x.zip!!a.js");
    member.files.push(escaped);
    assert!(!path_leaks(&member, &forbidden(traits)).is_empty());
}

#[test]
fn guard_ignores_archive_member_paths() {
    let clean = "/tmp/cleave-validate-a/0123456789abcdef/pkg.zip";
    let mut report = report_at(clean, "pkg.zip");
    report.finalize();
    let mut member = report.files[0].clone();
    member.path = format!("{clean}!!go/src/testdata/x.go##base64@3");
    member
        .kv
        .insert("file.basename".into(), serde_json::json!("testdata"));
    report.files.push(member);
    assert!(path_leaks(&report, &forbidden("/Users/x/traits-dev")).is_empty());
}

#[test]
fn relabel_rewrites_only_the_staged_root() {
    let neutral = "/t/h/a.js";
    let mut report = report_at(neutral, "a.js");
    report.finalize();
    let mut member = report.files[0].clone();
    member.path = format!("{neutral}##base64@4");
    report.files.push(member);
    let mut sibling = report.files[0].clone();
    sibling.path = "/t/h/a.jsx".into();
    report.files.push(sibling);

    relabel_paths(&mut report, neutral, "/fix/a.js");
    assert_eq!(report.files[0].path, "/fix/a.js");
    assert_eq!(report.files[1].path, "/fix/a.js##base64@4");
    assert_eq!(report.files[2].path, "/t/h/a.jsx");
}
