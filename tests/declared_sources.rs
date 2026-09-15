//! Harmless manifest/container regression: no fixture commands are executed.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::process::Command;

#[test]
fn declared_step_scopes_survive_archive_traversal_and_cached_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules/micro-behaviors/ui/terminal");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("traits.yaml"),
        r#"
defaults:
  for: [shell, github-actions]
  crit: notable
  conf: 1.0
traits:
  - id: first-output
    desc: Echo prints first literal
    if: {type: symbol, kind: call, exact: echo, arg: {kind: string, exact: first}}
  - id: second-output
    desc: Echo prints second literal
    if: {type: symbol, kind: call, exact: echo, arg: {kind: string, exact: second}}
composite_rules:
  - id: both-outputs
    desc: Both literals printed in one source unit
    all:
      - id: first-output
      - id: second-output
"#,
    )
    .unwrap();
    let sources = [
        (
            "separate/action.yml",
            "runs:\n  using: composite\n  steps:\n    - {shell: bash, run: \"echo 'first'\"}\n    - {shell: bash, run: \"echo 'second'\"}\n",
        ),
        (
            "together/action.yml",
            "runs:\n  using: composite\n  steps:\n    - {shell: bash, run: \"echo 'first'; echo 'second'\"}\n",
        ),
        (
            "quoted/action.yml",
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n        cat <<'DOC'\n        echo 'first'; echo 'second'\n        DOC\n",
        ),
    ];
    let archive_path = dir.path().join("fixtures.tar");
    let mut archive = tar::Builder::new(std::fs::File::create(&archive_path).unwrap());
    for (name, source) in sources {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
        let mut header = tar::Header::new_gnu();
        header.set_size(source.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, source.as_bytes())
            .unwrap();
    }
    archive.finish().unwrap();
    drop(archive);
    for memo in ["0", "64"] {
        let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
            .env("CLEAVE_TRAITS_DIR", dir.path().join("rules"))
            .env("CLEAVE_SKIP_CACHE", "1")
            .env("CLEAVE_ANALYSIS_MEMO_MB", memo)
            .env("FILEFACTS_CACHE", "0")
            .env("STNG_STRING_CACHE", "0")
            .args([
                "--disable",
                "yara,radare2,upx",
                "--no-update-check",
                "--json",
            ])
            .args([
                dir.path().join("separate/action.yml"),
                dir.path().join("together/action.yml"),
                dir.path().join("quoted/action.yml"),
                archive_path.clone(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reports: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&output.stdout)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(reports.len(), 4);
        for report in reports {
            let files = report["files"].as_array().unwrap();
            for file in files {
                let path = file["path"].as_str().unwrap();
                if !path.contains("/action.yml") {
                    continue;
                }
                let ids: Vec<_> = file["traits"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|t| t["id"].as_str())
                    .collect();
                assert_eq!(
                    ids.contains(&"micro-behaviors/ui/terminal::both-outputs"),
                    path.contains("together/action.yml"),
                    "memo={memo}, path={path}, ids={ids:?}"
                );
                if path.contains("!!/runs/steps/") {
                    assert_eq!(file["type"], "shell");
                    assert!(file.get("encoding").is_none());
                    assert!(file.get("pid").is_some(), "missing parent: {file}");
                    let parent = files
                        .iter()
                        .find(|candidate| candidate["id"] == file["pid"])
                        .unwrap();
                    assert_eq!(
                        parent["path"].as_str(),
                        path.rsplit_once("!!").map(|(parent, _)| parent)
                    );
                }
            }
            let root = files[0]["path"].as_str().unwrap();
            let expected = if root.ends_with("fixtures.tar") {
                4
            } else if root.contains("separate") {
                2
            } else {
                1
            };
            assert_eq!(
                files
                    .iter()
                    .filter(|f| f["path"].as_str().unwrap().contains("!!/runs/steps/"))
                    .count(),
                expected
            );
        }
    }
}
