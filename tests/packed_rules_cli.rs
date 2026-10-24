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

#[test]
fn cli_scans_packed_yaml_yara_and_precompiled_buckets() {
    let temp = tempfile::tempdir().unwrap();
    let plain = temp.path().join("plain");
    let packed = temp.path().join("packed");
    let relative = Path::new("metadata/probe");
    fs::create_dir_all(plain.join(relative)).unwrap();
    fs::write(plain.join(relative).join("traits.yaml"), TRAIT).unwrap();
    fs::write(plain.join(relative).join("probe.yar"), YARA).unwrap();

    let plain_compiled = plain.join("third-party/compiled");
    cleave::traits_repo::set_override_dir(Some(plain.clone()));
    let result = cleave::precompile_yara(&plain_compiled, true);
    cleave::traits_repo::set_override_dir(None);
    result.unwrap();

    pack(
        &plain.join(relative).join("traits.yaml"),
        &packed.join(relative).join("traits.yaml.zst"),
    );
    pack(
        &plain.join(relative).join("probe.yar"),
        &packed.join(relative).join("probe.yar.zst"),
    );
    let packed_compiled = packed.join("third-party/compiled");
    fs::create_dir_all(&packed_compiled).unwrap();
    fs::copy(
        plain_compiled.join("manifest.json"),
        packed_compiled.join("manifest.json"),
    )
    .unwrap();
    let mut buckets = Vec::new();
    for entry in fs::read_dir(&plain_compiled).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "yrc") {
            let name = format!("{}.zst", path.file_name().unwrap().to_string_lossy());
            let target = packed_compiled.join(name);
            pack(&path, &target);
            buckets.push(target);
        }
    }
    assert!(!buckets.is_empty(), "precompiler produced no YARA buckets");
    assert!(buckets.iter().all(|path| path.is_file()));

    let yara_sample = temp.path().join("yara-probe.php");
    fs::write(&yara_sample, "<?php /* cleave-packed-probe-marker */ ?>").unwrap();
    let yaml_sample = temp.path().join("yaml-probe.php");
    fs::write(
        &yaml_sample,
        r#"<?php $probe = "cleave-packed-probe-marker"; ?>"#,
    )
    .unwrap();
    let warm_cache = temp.path().join("warm-cache");
    let warm = run_scan(&packed, &warm_cache, &yara_sample);
    assert_match(&warm, "packed_probe_yara");
    assert_match(
        &run_scan(&packed, &warm_cache, &yaml_sample),
        "packed-probe",
    );
    let warm_log = String::from_utf8_lossy(&warm.stderr);
    assert!(
        warm_log.contains("Using shipped pre-compiled YARA rules"),
        "shipped bucket was not accepted: {warm_log}"
    );
    assert!(cached_buckets(&warm_cache).is_empty());

    // A corrupt shipped bucket must still detect from the packed source, and
    // its recovered local cache must use packed storage on Windows.
    for bucket in &buckets {
        fs::write(bucket, b"corrupt zstd").unwrap();
    }
    let fallback_cache = temp.path().join("fallback-cache");
    let fallback = run_scan(&packed, &fallback_cache, &yara_sample);
    assert_match(&fallback, "packed_probe_yara");
    assert_match(
        &run_scan(&packed, &fallback_cache, &yaml_sample),
        "packed-probe",
    );
    assert!(!cached_buckets(&fallback_cache).is_empty());
    #[cfg(windows)]
    assert!(
        cached_buckets(&fallback_cache)
            .iter()
            .all(|path| path.to_string_lossy().ends_with(".yrc.zst"))
    );
}
