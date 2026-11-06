#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use std::io::Write;
use std::time::Duration;

#[cfg(unix)]
#[test]
fn a_cache_dir_other_users_can_write_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let shared = tmp.path().join("shared");
    create_private_dir(&shared).unwrap();
    assert_eq!(
        fs::metadata(&shared).unwrap().permissions().mode() & 0o777,
        0o700
    );
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(create_private_dir(&shared).is_err());
}

#[test]
fn cached_values_round_trip_through_the_bounded_decoder() {
    let small = zstd::encode_all(&b"ok"[..], 1).unwrap();
    assert_eq!(decode_cached_zstd(small.as_slice()).unwrap(), b"ok");
}

/// A traits tree with one YARA rule file and one plain trait file.
fn traits_tree(dir: &Path) -> (PathBuf, PathBuf) {
    let rule = dir.join("third-party/vendor/rules.yar");
    fs::create_dir_all(rule.parent().unwrap()).unwrap();
    fs::write(&rule, b"rule a { strings: $s = \"abc\" condition: $s }\n").unwrap();
    let trait_file = dir.join("micro-behaviors/net/socket.yaml");
    fs::create_dir_all(trait_file.parent().unwrap()).unwrap();
    fs::write(
        &trait_file,
        b"traits:\n  - id: net/socket\n    if: {type: string, value: connect}\n",
    )
    .unwrap();
    (rule, trait_file)
}

/// Hash the rule sources under `traits_dir` as they stand on disk.
fn compute_rules_source_tag(traits_dir: &Path) -> Option<u64> {
    let sources = crate::rule_sources::RuleSources::fresh(traits_dir).ok()?;
    source_tag_from_snapshot(traits_dir, &sources)
}

/// The failure this tag exists to catch: a rule edit that leaves the file's
/// length untouched, which a path+length fingerprint cannot see.
#[test]
fn test_source_tag_catches_same_length_rule_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let (rule, _) = traits_tree(tmp.path());
    let before = compute_rules_source_tag(tmp.path()).expect("tag");

    fs::write(&rule, b"rule a { strings: $s = \"abd\" condition: $s }\n").unwrap();
    let after = compute_rules_source_tag(tmp.path()).expect("tag");

    assert_ne!(before, after, "same-length rule edit must change the tag");
}

/// The churn this tag exists to avoid: trait YAML with no inline rule
/// cannot change a compiled `.yrc`, so editing it must not condemn one.
#[test]
fn test_source_tag_ignores_trait_yaml_without_inline_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, trait_file) = traits_tree(tmp.path());
    let before = compute_rules_source_tag(tmp.path()).expect("tag");

    fs::write(
        &trait_file,
        b"traits:\n  - id: net/socket\n    if: {type: string, value: connect}\n    description: a much longer file now\n",
    )
    .unwrap();
    fs::create_dir_all(tmp.path().join("well-known")).unwrap();
    fs::write(tmp.path().join("well-known/added.yaml"), b"traits: []\n").unwrap();

    assert_eq!(
        before,
        compute_rules_source_tag(tmp.path()).expect("tag"),
        "trait YAML with no inline YARA must not move the tag"
    );
}

/// Inline `type: yara` rules do reach the compiler, so their file is
/// fingerprinted by content like any `.yar`.
#[test]
fn test_source_tag_tracks_inline_yara_yaml() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, trait_file) = traits_tree(tmp.path());
    let inline = tmp.path().join("objectives/impact/wiper.yaml");
    fs::create_dir_all(inline.parent().unwrap()).unwrap();
    let rule_of = |marker: &str| {
        format!(
            "traits:\n  - id: impact/wiper\n    if:\n      type: yara\n      source: |\n        rule w {{ strings: $s = \"{marker}\" condition: $s }}\n"
        )
    };
    fs::write(&inline, rule_of("wipe")).unwrap();
    let before = compute_rules_source_tag(tmp.path()).expect("tag");

    fs::write(&inline, rule_of("nuke")).unwrap();
    let after = compute_rules_source_tag(tmp.path()).expect("tag");
    assert_ne!(before, after, "inline YARA edit must change the tag");

    // The plain trait file next to it still contributes nothing.
    fs::write(&trait_file, b"traits: []\n").unwrap();
    assert_eq!(after, compute_rules_source_tag(tmp.path()).expect("tag"));
}

/// The tag travels with a bundle, so it must depend on the tree's contents
/// and layout — never on where that tree happens to sit.
#[test]
fn test_source_tag_is_independent_of_traits_dir_location() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    traits_tree(one.path());
    traits_tree(two.path());

    assert_eq!(
        compute_rules_source_tag(one.path()).expect("tag"),
        compute_rules_source_tag(two.path()).expect("tag"),
    );
}

#[test]
fn test_yara_cache_key_format() {
    // Test that cache key has expected format
    let key = yara_cache_key(false);
    assert!(key.starts_with("yara-rules-v5-"));
    assert!(key.ends_with("-builtin"));

    let key = yara_cache_key(true);
    assert!(key.starts_with("yara-rules-v5-"));
    assert!(key.ends_with("-with-3p"));
}

#[test]
fn test_rule_files_revision_changes_for_same_second_edits() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let traits_dir = tmp.path();
    let rule = traits_dir.join("traits.yaml");
    fs::write(&rule, b"traits: []\n").expect("write rule");

    let fixed = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    filetime::set_file_mtime(&rule, filetime::FileTime::from_system_time(fixed))
        .expect("set mtime");

    // Walk the directory directly (not the memoized `traits_scan`) so both
    // reads reflect the file as it stands, exercising the same-second
    // fingerprint change.
    let first = scan_traits_dir(traits_dir)
        .rule_revision
        .expect("first revision");

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&rule)
        .expect("open rule");
    file.write_all(b"# edit in same second\n").expect("append");
    filetime::set_file_mtime(&rule, filetime::FileTime::from_system_time(fixed))
        .expect("reset mtime");
    let second = scan_traits_dir(traits_dir)
        .rule_revision
        .expect("second revision");

    assert_eq!(first.newest_mtime, second.newest_mtime);
    assert_ne!(first.fingerprint, second.fingerprint);
}

/// Rewrite `path` with `contents` and put its mtime back, so only the bytes
/// differ from what a stat key would see.
fn rewrite_keeping_mtime(path: &Path, contents: &str) {
    let mtime = fs::metadata(path).unwrap().modified().unwrap();
    let len = fs::metadata(path).unwrap().len();
    fs::write(path, contents).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), mtime);
    assert_eq!(fs::metadata(path).unwrap().len(), len);
}

// The edit a stat key cannot see: same path, same length, same mtime.
#[test]
fn same_length_edit_with_mtime_restored_changes_every_revision() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, trait_file) = traits_tree(tmp.path());
    let before = scan_traits_dir(tmp.path());

    rewrite_keeping_mtime(
        &trait_file,
        "traits:\n  - id: net/socket\n    if: {type: string, value: cOnnect}\n",
    );
    let after = scan_traits_dir(tmp.path());

    assert_ne!(
        after.rule_revision.unwrap().fingerprint,
        before.rule_revision.unwrap().fingerprint,
        "analysis-cache revision"
    );
    assert_ne!(
        after.yaml_revision.unwrap().fingerprint,
        before.yaml_revision.unwrap().fingerprint,
        "mapper-cache revision"
    );
    assert_ne!(after.content.rules, before.content.rules);
    assert_eq!(after.content.layout, before.content.layout);
}

// Content keys neither trust mtimes nor depend on them: a checkout that
// restamps every file must keep every cache entry.
#[test]
fn touching_files_changes_no_revision() {
    let tmp = tempfile::tempdir().unwrap();
    let (rule, trait_file) = traits_tree(tmp.path());
    let before = scan_traits_dir(tmp.path());
    let later = SystemTime::UNIX_EPOCH + Duration::from_secs(1_900_000_000);
    for path in [&rule, &trait_file] {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(later)
            .unwrap();
    }
    let after = scan_traits_dir(tmp.path());
    assert_eq!(
        after.rule_revision.unwrap().fingerprint,
        before.rule_revision.unwrap().fingerprint
    );
    assert_eq!(
        after.yaml_revision.unwrap().fingerprint,
        before.yaml_revision.unwrap().fingerprint
    );
    assert_eq!(after.content, before.content);
    assert_ne!(
        after.rule_revision.unwrap().newest_mtime,
        before.rule_revision.unwrap().newest_mtime
    );
}

/// A one-trait tree whose trait description is `desc`.
fn probe_tree(desc: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("objectives/probe/memo.yaml");
    fs::create_dir_all(yaml.parent().unwrap()).unwrap();
    fs::write(&yaml, probe_yaml(desc)).unwrap();
    dir
}

fn probe_yaml(desc: &str) -> String {
    format!(
        "traits:\n  - id: memo-probe\n    desc: {desc}\n    crit: notable\n    \
             conf: 0.8\n    for: [python]\n    if:\n      type: text\n      \
             exact: memo-probe-needle\n"
    )
}

fn load_probe_desc(dir: &Path, full_validation: bool) -> Option<String> {
    let mapper = crate::capabilities::CapabilityMapper::from_directory_with_options(
        dir,
        crate::LoadOptions {
            full_validation,
            ..crate::LoadOptions::default()
        },
    )
    .unwrap();
    mapper
        .trait_definitions()
        .iter()
        .find(|t| t.id.ends_with("memo-probe"))
        .map(|t| t.desc.clone())
}

// The mapper cache written for one tree must not be served for a
// same-length edit of it under a restored mtime, whether the load
// validates nothing or skips validation on a clean mark. Invalidating the
// scan stands in for the next process, which reads the tree afresh.
#[test]
fn mapper_cache_misses_on_a_same_length_edit() {
    let dir = probe_tree("probe aaa");
    let yaml = dir.path().join("objectives/probe/memo.yaml");
    assert_eq!(
        load_probe_desc(dir.path(), false).as_deref(),
        Some("probe aaa")
    );
    assert!(mapper_cache_path_for(dir.path()).unwrap().exists());

    rewrite_keeping_mtime(&yaml, &probe_yaml("probe bbb"));
    invalidate_traits_scan();
    assert_eq!(
        load_probe_desc(dir.path(), false).as_deref(),
        Some("probe bbb")
    );

    // Full validation requested, skipped on a mark for the edited tree.
    rewrite_keeping_mtime(&yaml, &probe_yaml("probe ccc"));
    invalidate_traits_scan();
    // Marks are off under `make test` (CLEAVE_SKIP_CACHE=1), and this probe
    // tree fails full validation, so there is no skip to exercise.
    let Some(mark) = crate::traits_fingerprint::CleanMark::for_traits(dir.path(), None) else {
        return;
    };
    mark.set_if_unchanged(dir.path());
    assert_eq!(
        load_probe_desc(dir.path(), true).as_deref(),
        Some("probe ccc")
    );
}

#[test]
fn test_cache_dir_returns_path() {
    let result = cache_dir();
    // Should either succeed or fail, but not panic
    match result {
        Ok(path) => {
            assert!(path.to_string_lossy().contains("cleave"));
        }
        Err(_) => {
            // Some environments may not have cache dir
        }
    }
}

#[test]
fn test_yara_cache_path_includes_cache_key() {
    if let Ok(path) = yara_cache_path(false) {
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("yara-rules-v5-"));
    }
}

#[test]
fn test_yara_cache_path_different_for_third_party() {
    if let (Ok(path1), Ok(path2)) = (yara_cache_path(false), yara_cache_path(true)) {
        // Paths should be different based on third_party flag
        assert_ne!(path1, path2);
        assert!(path1.to_string_lossy().contains("builtin"));
        assert!(path2.to_string_lossy().contains("with-3p"));
    }
}

#[test]
fn test_most_recent_yara_mtime_no_files() {
    // This test verifies the function handles missing directories gracefully.
    // Note: We don't change the working directory as that would affect parallel tests.
    // The actual behavior depends on whether yara/ exists in the project root.
    // If yara/ exists with files, it returns Ok; if not, it returns Err.
    let result = most_recent_yara_mtime();
    // Just verify it doesn't panic - result depends on project structure
    let _ = result;
}

#[test]
fn test_cleanup_old_caches_handles_nonexistent_dir() {
    let temp_path = PathBuf::from("/nonexistent/cache/file.bin");
    // Should not panic with nonexistent path
    let _ = cleanup_old_caches(&temp_path);
}

#[test]
fn mapper_family_strips_timestamp_and_fingerprint() {
    assert_eq!(
        mapper_family("capability-mapper-v7-2.3.0-aaaaaaaa-100-000000000000000a.bin"),
        "capability-mapper-v7-2.3.0-aaaaaaaa"
    );
    // A pre-release version keeps its internal dash inside the family.
    assert_eq!(
        mapper_family("capability-mapper-v7-2.3.0-rc1-bbbbbbbb-200-000000000000000b.bin"),
        "capability-mapper-v7-2.3.0-rc1-bbbbbbbb"
    );
}

#[test]
fn prune_superseded_mappers_keeps_newest_per_family() {
    let dir = std::env::temp_dir().join(format!("cleave-mapper-prune-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    // Family A (dir_tag aaaaaaaa): an old and a new version. Family B
    // (dir_tag bbbbbbbb): a single, still-valid mapper for another
    // traits-dir — it must survive even though it is older than A's newest.
    let a_old = "capability-mapper-v7-2.3.0-aaaaaaaa-100-000000000000000a.bin";
    let a_new = "capability-mapper-v7-2.3.0-aaaaaaaa-300-000000000000000b.bin";
    let b_one = "capability-mapper-v7-2.3.0-bbbbbbbb-200-000000000000000c.bin";
    for (name, hours_old) in [(a_old, 3u64), (b_one, 2), (a_new, 1)] {
        let f = fs::File::create(dir.join(name)).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(hours_old * 3600))
            .unwrap();
    }
    fs::write(dir.join("yara-rules-v4-x-builtin"), b"keep").unwrap();

    prune_superseded_mappers(&dir);

    assert!(
        !dir.join(a_old).exists(),
        "superseded family-A version pruned"
    );
    assert!(dir.join(a_new).exists(), "current family-A mapper retained");
    assert!(
        dir.join(b_one).exists(),
        "another traits-dir's mapper is never pruned across families"
    );
    assert!(
        dir.join("yara-rules-v4-x-builtin").exists(),
        "non-mapper files are untouched"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_format_age() {
    assert_eq!(format_age(0), "0s");
    assert_eq!(format_age(45), "45s");
    assert_eq!(format_age(60), "1m 0s");
    assert_eq!(format_age(90), "1m 30s");
    assert_eq!(format_age(3600), "1h 0m");
    assert_eq!(format_age(3661), "1h 1m");
    assert_eq!(format_age(86400), "1d 0h");
    assert_eq!(format_age(90061), "1d 1h");
}

/// A family whose newest mapper went unused past the TTL is dropped whole,
/// so caches for removed checkouts and temporary trees do not pile up; a
/// family used recently keeps its newest mapper.
#[test]
fn prune_drops_mapper_families_unused_past_the_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let stale = dir
        .path()
        .join("capability-mapper-v14-3.0.0-deadbeef-0000000000000001-aaaaaaaaaaaaaaaa.bin");
    let fresh = dir
        .path()
        .join("capability-mapper-v14-3.0.0-cafef00d-0000000000000001-bbbbbbbbbbbbbbbb.bin");
    std::fs::write(&stale, b"x").unwrap();
    std::fs::write(&fresh, b"x").unwrap();
    let long_ago =
        std::time::SystemTime::now() - UNUSED_MAPPER_TTL - std::time::Duration::from_secs(60);
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(long_ago)
        .unwrap();
    prune_superseded_mappers(dir.path());
    assert!(!stale.exists(), "an unused family is pruned");
    assert!(fresh.exists(), "a recently used family is kept");
    // Use refreshes the age.
    std::fs::File::options()
        .write(true)
        .open(&fresh)
        .unwrap()
        .set_modified(long_ago)
        .unwrap();
    mark_used(&fresh);
    prune_superseded_mappers(dir.path());
    assert!(fresh.exists(), "marking a mapper used keeps it");
}
