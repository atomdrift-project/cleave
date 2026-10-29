//! Exercise packed rule sources and shipped YARA buckets through the CLI.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TRAIT: &str = r#"
defaults:
  for: [php]
  crit: suspicious
  conf: 1.0
traits:
  - id: packed-probe
    desc: Packed rule integration probe
    if:
      type: text
      substr: cleave-packed-probe-marker
"#;

const YARA: &str = r#"
rule packed_probe_yara {
  meta:
    filetype = "php"
    score = 70
  strings:
    $marker = "cleave-packed-probe-marker"
  condition:
    $marker
}
"#;

fn pack(source: &Path, target: &Path) {
    let bytes = fs::read(source).unwrap();
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::write(target, zstd::encode_all(&bytes[..], 3).unwrap()).unwrap();
}

fn run_scan(rules: &Path, cache: &Path, sample: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cleave"))
        .env("CLEAVE_TRAITS_DIR", rules)
        .env("CLEAVE_CACHE_DIR", cache)
        .env("RUST_LOG", "cleave::yara_engine=info")
        .env("FILEFACTS_CACHE", "0")
        .env_remove("CLEAVE_SKIP_CACHE")
        .env_remove("CLEAVE_SKIP_YARA_CACHE")
        .env_remove("CLEAVE_SKIP_YARA")
        .env_remove("CLEAVE_BUILTIN_YARA_ONLY")
        .args([
            "--no-update-check",
            "--format",
            "json",
            "--disable",
            "radare2,upx",
        ])
        .arg("analyze")
        .arg(sample)
        .output()
        .unwrap()
}

fn assert_match(output: &Output, expected: &str) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let text = report.to_string();
    assert!(text.contains(expected), "missing {expected}: {text}");
}

fn cached_buckets(cache: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(cache)
        .into_iter()
        .filter_map(Result::ok)
        .map(walkdir::DirEntry::into_path)
        .filter(|path| {
            path.is_file()
                && (path.extension().is_some_and(|ext| ext == "yrc")
                    || path.to_string_lossy().ends_with(".yrc.zst"))
        })
        .collect()
}

/// Packed rule sources scan like plain ones, and a traits tree's own
/// `third-party/compiled/` is never loaded — not even a valid one: a compiled
/// bucket is native code, so it only ever comes from this host's cache.
#[test]
fn cli_scans_packed_yaml_yara_and_ignores_shipped_buckets() {
    let temp = tempfile::tempdir().unwrap();
    let plain = temp.path().join("plain");
    let packed = temp.path().join("packed");
    let relative = Path::new("metadata/probe");
    fs::create_dir_all(plain.join(relative)).unwrap();
    fs::write(plain.join(relative).join("traits.yaml"), TRAIT).unwrap();
    fs::write(plain.join(relative).join("probe.yar"), YARA).unwrap();

    pack(
        &plain.join(relative).join("traits.yaml"),
        &packed.join(relative).join("traits.yaml.zst"),
    );
    pack(
        &plain.join(relative).join("probe.yar"),
        &packed.join(relative).join("probe.yar.zst"),
    );
    // A valid precompiled set beside the sources, as an older bundle shipped.
    let shipped = packed.join("third-party/compiled");
    cleave::traits_repo::set_override_dir(Some(plain.clone()));
    let result = cleave::precompile_yara(&shipped, true);
    cleave::traits_repo::set_override_dir(None);
    result.unwrap();

    let yara_sample = temp.path().join("yara-probe.php");
    fs::write(&yara_sample, "<?php /* cleave-packed-probe-marker */ ?>").unwrap();
    let yaml_sample = temp.path().join("yaml-probe.php");
    fs::write(
        &yaml_sample,
        r#"<?php $probe = "cleave-packed-probe-marker"; ?>"#,
    )
    .unwrap();
    let cache = temp.path().join("cache");
    let scan = run_scan(&packed, &cache, &yara_sample);
    assert_match(&scan, "packed_probe_yara");
    assert_match(&run_scan(&packed, &cache, &yaml_sample), "packed-probe");
    let log = String::from_utf8_lossy(&scan.stderr);
    assert!(
        !log.contains("shipped pre-compiled"),
        "a shipped bucket was loaded: {log}"
    );
    assert!(
        !cached_buckets(&cache).is_empty(),
        "buckets must compile into the local cache"
    );
    #[cfg(windows)]
    assert!(
        cached_buckets(&cache)
            .iter()
            .all(|path| path.to_string_lossy().ends_with(".yrc.zst"))
    );
}
