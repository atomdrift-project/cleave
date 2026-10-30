//! Uniform directory limits apply to formerly exempt catalogs and partitions.

use std::path::Path;
use std::process::Command;

fn write_catalog(root: &Path, namespace: &str, count: usize) {
    let leaf = root.join(namespace);
    std::fs::create_dir_all(&leaf).unwrap();
    let fixtures = root.join("testdata/baseline");
    std::fs::create_dir_all(&fixtures).unwrap();
    std::fs::write(fixtures.join("control.txt"), "ordinary fixture content\n").unwrap();
    let marker = namespace.replace('/', "_");
    let mut yaml = String::from(
        "defaults:\n  platforms: [unix, windows]\n  for: [text]\n  crit: notable\ntraits:\n",
    );
    for index in 0..count {
        yaml.push_str(&format!(
            "  - id: reviewed-property-{index}\n    desc: Reviewed static property {index}\n    conf: 0.9\n    if: {{type: text, exact: {marker}_property_{index:04}}}\n"
        ));
    }
    std::fs::write(leaf.join("catalog.yaml"), yaml).unwrap();
}

/// `cleave validate` over `root`: whether it passed, and its report.
fn validate(root: &Path) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
        .args([
            "--traits-dir",
            root.to_str().unwrap(),
            "validate",
            "--exclude",
            "validation",
        ])
        .env("CLEAVE_SKIP_CACHE", "1")
        .env_remove("CLEAVE_VALIDATE_SOFT")
        .output()
        .unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The per-directory rule budget the binary enforces, read from its own
/// oversized-directory report so these tests follow the configured limit.
fn directory_budget() -> usize {
    static BUDGET: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *BUDGET.get_or_init(|| {
        let temp = tempfile::tempdir().unwrap();
        write_catalog(temp.path(), "metadata/file/naming", 1000);
        let (_, stderr) = validate(temp.path());
        stderr
            .lines()
            .find_map(|line| {
                let rest = line.split("(limit ").nth(1)?;
                rest.trim_end_matches(')').parse().ok()
            })
            .unwrap_or_else(|| panic!("no directory budget in the report: {stderr}"))
    })
}

#[test]
fn former_exempt_catalogs_accept_the_budget_and_reject_one_more() {
    let budget = directory_budget();
    for namespace in [
        "metadata/file/naming",
        "metadata/filename",
        "metadata/path",
        "metadata/archive/member/filename",
        "metadata/file/archive",
        "metadata/package/dependencies/manifest/identity",
        "micro-behaviors/data/decode/base64",
        "micro-behaviors/fs/file/copy",
        "objectives/exfiltration/stealer/credential",
        "micro-behaviors/communications/http/header/custom",
        "micro-behaviors/communications/http/post",
        "micro-behaviors/communications/http/request/body",
        "micro-behaviors/communications/http/upload",
        "micro-behaviors/communications/http/url/path",
        "micro-behaviors/fs/path/credential",
        "micro-behaviors/fs/write/file/full",
        "micro-behaviors/os/user/account",
        "metadata/lang/source/literal",
    ] {
        let temp = tempfile::tempdir().unwrap();
        for (count, accepted) in [(budget, true), (budget + 1, false)] {
            write_catalog(temp.path(), namespace, count);
            let (ok, stderr) = validate(temp.path());
            assert_eq!(ok, accepted, "{namespace} with {count} rules: {stderr}");
            if !accepted {
                assert!(stderr.contains("policy/oversized-dir"), "{stderr}");
                assert!(stderr.contains(namespace), "{stderr}");
            }
        }
    }
}

/// Sibling sparseness is advice, not a gate: a two-child partition loads at
/// any size, and the soft sparse-sibling warning needs ten or more children.
#[test]
fn former_sparse_partition_is_accepted_at_any_size() {
    let temp = tempfile::tempdir().unwrap();
    for second_count in [17, 18] {
        write_catalog(temp.path(), "micro-behaviors/fs/swap/on", 17);
        write_catalog(temp.path(), "micro-behaviors/fs/swap/off", second_count);
        let (ok, stderr) = validate(temp.path());
        assert!(ok, "{stderr}");
        assert!(!stderr.contains("sparse-siblings"), "{stderr}");
    }
}

#[test]
fn artifact_subject_roots_are_admitted_with_narrow_platform_contracts() {
    for (namespace, portable, accepted) in [
        ("metadata/archive/member/filename", false, true),
        ("metadata/archive/layout", true, false),
        ("metadata/filename", true, true),
        ("metadata/path", true, true),
        ("metadata/arch", true, false),
        ("metadata/not-an-artifact-subject", false, false),
    ] {
        let temp = tempfile::tempdir().unwrap();
        write_catalog(temp.path(), namespace, 1);
        if portable {
            let path = temp.path().join(namespace).join("catalog.yaml");
            let yaml = std::fs::read_to_string(&path).unwrap();
            std::fs::write(path, yaml.replace("[unix, windows]", "[all]")).unwrap();
        }
        let (ok, stderr) = validate(temp.path());
        if namespace == "metadata/not-an-artifact-subject" {
            // The existing unknown-directory check emits its diagnostic at
            // load time; its CLI exit policy is outside this admission change.
            assert!(
                stderr.contains("Unknown metadata/ subdirectory"),
                "{stderr}"
            );
        } else {
            assert_eq!(ok, accepted, "{namespace}: {stderr}");
            assert!(
                !stderr.contains("Unknown metadata/ subdirectory"),
                "{stderr}"
            );
        }
        if !accepted && namespace != "metadata/not-an-artifact-subject" {
            assert!(stderr.contains(namespace), "{stderr}");
        }
    }
}

#[test]
fn mixed_credential_values_can_occupy_the_item_ancestor_without_a_larger_budget() {
    let budget = directory_budget();
    let temp = tempfile::tempdir().unwrap();
    for (count, accepted) in [(budget, true), (budget + 1, false)] {
        write_catalog(
            temp.path(),
            "objectives/exfiltration/stealer/credential/value",
            count,
        );
        write_catalog(
            temp.path(),
            "objectives/exfiltration/stealer/credential/value/key",
            1,
        );
        let (ok, stderr) = validate(temp.path());
        assert_eq!(ok, accepted, "{stderr}");
        assert!(!stderr.contains("policy/leaf-yaml"), "{stderr}");
        if !accepted {
            assert!(stderr.contains("policy/oversized-dir"), "{stderr}");
        }
    }
}

#[test]
fn archive_family_scope_follows_the_shared_fact_producer() {
    for (path, extra, accepted) in [
        ("archive.members[*].path", "", true),
        ("archive.members[*].path", ", -zip", true),
        ("archive.members[*].path", ", pe", false),
        ("unrelated.name", "", false),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let leaf = temp.path().join("metadata/archive/member/path");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::create_dir_all(temp.path().join("testdata/baseline")).unwrap();
        std::fs::write(
            temp.path().join("testdata/baseline/plain.txt"),
            "ordinary input",
        )
        .unwrap();
        std::fs::write(leaf.join("scope.yaml"), format!(
            "defaults:\n  platforms: [unix, windows, android]\n  for: [archives{extra}]\n  crit: notable\ntraits:\n- id: recorded-path\n  desc: Recorded archive member path\n  if: {{type: value, path: '{path}', exact: sentinel}}\n"
        )).unwrap();
        let (_, stderr) = validate(temp.path());
        // The CLI currently reports broad-scope diagnostics without changing
        // its exit status when validation is excluded, so inspect the report.
        assert_eq!(
            stderr.contains("traits exceed the file-type cap"),
            !accepted,
            "{path} {extra}: {stderr}"
        );
    }
}
