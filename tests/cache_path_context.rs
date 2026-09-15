//! Content-equal source files must not share path-dependent verdicts.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::process::Command;

fn fixture() -> (tempfile::TempDir, Vec<std::path::PathBuf>) {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("rules/metadata/build/entrypoint");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("traits.yaml"),
        r#"defaults:
  for: [rust]
  crit: notable
  conf: 1.0
traits:
  - id: build-script-name
    desc: Rust build script filename
    if:
      type: basename
      exact: build.rs
  - id: ready-function
    desc: Ready function outside test directories
    if:
      type: text
      substr: pub fn ready
    unless:
      - type: path
        substr: /tests/
"#,
    )
    .unwrap();
    let names = [
        "ordinary/lib.rs",
        "ordinary/build.rs",
        "tests/lib.rs",
        "other/build.rs",
    ];
    let paths: Vec<_> = names.iter().map(|name| dir.path().join(name)).collect();
    for path in &paths {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "pub fn ready() {}\n").unwrap();
    }
    (dir, paths)
}

#[test]
fn cache_preserves_filename_and_negative_path_conditions() {
    let (dir, paths) = fixture();
    for order in [[0, 1, 2, 3], [2, 1, 0, 3], [1, 0, 3, 2]] {
        for memo in ["0", "64"] {
            let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
                .env("RAYON_NUM_THREADS", "1")
                .env("CLEAVE_SKIP_CACHE", "1")
                .env("CLEAVE_ANALYSIS_MEMO_MB", memo)
                .env("FILEFACTS_CACHE", "0")
                .env("STNG_STRING_CACHE", "0")
                .env("CLEAVE_TRAITS_DIR", dir.path().join("rules"))
                .args([
                    "--disable",
                    "yara,radare2,upx",
                    "--no-update-check",
                    "--json",
                ])
                .args(order.iter().map(|i| &paths[*i]))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            let reports: Vec<serde_json::Value> = serde_json::Deserializer::from_str(&stdout)
                .into_iter()
                .collect::<Result<_, _>>()
                .expect(&stdout);
            assert_eq!(reports.len(), paths.len(), "{stdout}");
            for report in reports {
                let root = &report["files"][0];
                let path = root["path"].as_str().unwrap();
                let mut expected = BTreeSet::new();
                if path.ends_with("/build.rs") {
                    expected.insert("metadata/build/entrypoint::build-script-name");
                }
                if !path.contains("/tests/") {
                    expected.insert("metadata/build/entrypoint::ready-function");
                }
                let actual: BTreeSet<_> = root["traits"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|t| t["id"].as_str())
                    .filter(|id| id.starts_with("metadata/build/entrypoint::"))
                    .collect();
                assert_eq!(
                    actual, expected,
                    "memo={memo}, order={order:?}, path={path}"
                );
            }
        }
    }
}

#[test]
fn cache_preserves_archive_and_memory_api_context() {
    if let Ok(root) = std::env::var("CLEAVE_CACHE_CONTEXT_CHILD") {
        let root = std::path::Path::new(&root);
        cleave::traits_repo::set_override_dir(Some(root.join("rules")));
        let options = cleave::AnalysisOptions {
            disable_yara: true,
            disable_radare2: true,
            disable_upx: true,
            ..Default::default()
        };
        // Only harmless source text is packaged; nothing is compiled or run.
        // Start with members to exercise the compact FileAnalysis cache too.
        let archive_path = root.join("package.tar");
        let mut archive = tar::Builder::new(std::fs::File::create(&archive_path).unwrap());
        const SOURCE: &[u8] = b"pub fn ready() {}\n";
        for name in [
            "pkg/lib.rs",
            "pkg/build.rs",
            "pkg/tests/lib.rs",
            "other/build.rs",
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(SOURCE.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, name, SOURCE).unwrap();
        }
        archive.finish().unwrap();
        drop(archive);
        let report = cleave::analyze_file(&archive_path, &options).unwrap();
        assert_eq!(report.files.len(), 4);
        for member in &report.files {
            assert_context(&member.path, member.findings.iter().map(|f| f.id.as_str()));
        }

        for (index, name) in [
            "ordinary/lib.rs",
            "ordinary/build.rs",
            "tests/lib.rs",
            "other/build.rs",
        ]
        .iter()
        .enumerate()
        {
            let path = root.join(name);
            let path = path.to_str().unwrap();
            let report = match index {
                0 => cleave::analyze_bytes_owned(SOURCE.to_vec(), path, &options),
                1 => {
                    cleave::analyze_bytes_shared(bytes::Bytes::from_static(SOURCE), path, &options)
                }
                2 => cleave::analyze_bytes(SOURCE, path, &options),
                _ => cleave::analyze_file(path, &options),
            }
            .unwrap();
            assert_eq!(report.target.path, path);
            assert_context(path, report.findings.iter().map(|f| f.id.as_str()));
        }
        // Equivalence checks must retain useful cross-path sharing.
        let warm = root.join("warm/lib.rs");
        let _ =
            cleave::analyze_bytes_owned(SOURCE.to_vec(), warm.to_str().unwrap(), &options).unwrap();
        let equivalent = root.join("equivalent/lib.rs");
        let report = cleave::analyze_bytes_shared(
            bytes::Bytes::from_static(SOURCE),
            equivalent.to_str().unwrap(),
            &options,
        )
        .unwrap();
        assert!(
            report.cache_hit,
            "equivalent paths should still share an analysis"
        );
        assert_eq!(report.target.path, equivalent.to_str().unwrap());
        return;
    }
    // Process isolation keeps the environment and global mapper independent
    // of the other tests, while allowing a real warm in-process cache.
    let (dir, _) = fixture();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "cache_preserves_archive_and_memory_api_context",
            "--nocapture",
        ])
        .env("CLEAVE_CACHE_CONTEXT_CHILD", dir.path())
        .env("CLEAVE_SKIP_CACHE", "1")
        .env("CLEAVE_ANALYSIS_MEMO_MB", "64")
        .env("RAYON_NUM_THREADS", "1")
        .env("FILEFACTS_CACHE", "0")
        .env("STNG_STRING_CACHE", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_context<'a>(path: &str, ids: impl Iterator<Item = &'a str>) {
    let actual: BTreeSet<_> = ids
        .filter(|id| id.starts_with("metadata/build/entrypoint::"))
        .collect();
    let mut expected = BTreeSet::new();
    if path.ends_with("/build.rs") {
        expected.insert("metadata/build/entrypoint::build-script-name");
    }
    if !path.contains("/tests/") {
        expected.insert("metadata/build/entrypoint::ready-function");
    }
    assert_eq!(actual, expected, "{path}");
}
