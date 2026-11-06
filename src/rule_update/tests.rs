use super::*;

#[test]
fn packed_install_keeps_rule_bytes_out_of_plain_files() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    std::fs::create_dir(&staging).unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in [
        ("metadata/probe/traits.yaml", b"name: probe".as_slice()),
        (
            "third-party/rule.yar",
            b"rule probe { condition: true }".as_slice(),
        ),
        ("third-party/compiled/php.yrc", b"compiled probe".as_slice()),
        ("third-party/config.yaml", b"config: probe".as_slice()),
        ("testdata/expectations.yaml", b"test: probe".as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }
    let archive = builder.into_inner().unwrap();
    unpack_bundle(Cursor::new(&archive), &staging, true).unwrap();
    let plain = tmp.path().join("plain");
    std::fs::create_dir(&plain).unwrap();
    unpack_bundle(Cursor::new(archive), &plain, false).unwrap();

    for (path, bytes) in [
        ("metadata/probe/traits.yaml", b"name: probe".as_slice()),
        (
            "third-party/rule.yar",
            b"rule probe { condition: true }".as_slice(),
        ),
    ] {
        assert!(!staging.join(path).exists());
        assert!(staging.join(format!("{path}.zst")).is_file());
        let sources = crate::rule_sources::RuleSources::fresh(&staging).unwrap();
        assert_eq!(&*sources.file(Path::new(path)).unwrap().bytes, bytes);
    }
    // Compiled rules are native code: a bundle's are never installed.
    for root in [&staging, &plain] {
        let compiled = root.join("third-party/compiled/php.yrc");
        assert!(!compiled.exists() && !compiled.with_extension("yrc.zst").exists());
    }
    assert_eq!(
        std::fs::read(staging.join("third-party/config.yaml")).unwrap(),
        b"config: probe"
    );
    assert_eq!(
        std::fs::read(staging.join("testdata/expectations.yaml")).unwrap(),
        b"test: probe"
    );
    let packed_sources = crate::rule_sources::RuleSources::fresh(&staging).unwrap();
    let plain_sources = crate::rule_sources::RuleSources::fresh(&plain).unwrap();
    assert_eq!(
        crate::cache::source_tag_from_snapshot(&staging, &packed_sources),
        crate::cache::source_tag_from_snapshot(&plain, &plain_sources)
    );
}

#[test]
fn bundle_rejects_links_before_the_sidecar_write_can_follow_them() {
    let tmp = tempfile::tempdir().unwrap();
    let staging = tmp.path().join("staging");
    std::fs::create_dir(&staging).unwrap();
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, "unchanged").unwrap();

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::symlink());
    header.set_size(0);
    header.set_mode(0o777);
    header.set_link_name(&victim).unwrap();
    header.set_cksum();
    builder
        .append_data(&mut header, SIDECAR, std::io::empty())
        .unwrap();
    let archive = builder.into_inner().unwrap();

    let error = unpack_bundle(Cursor::new(archive), &staging, false).unwrap_err();
    assert!(error.contains("unsupported tar entry type Symlink"));
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "unchanged");
    assert!(std::fs::symlink_metadata(staging.join(SIDECAR)).is_err());
}

#[test]
fn a_refusal_says_what_was_wrong_and_what_to_do() {
    use crate::enriched::Source;
    let tid = "8f2d0497b4e2c5a7";
    let community = refusal(tid, Source::File, &Answer::Public(Some("free".into())));
    assert!(
        community.contains("free plan") && community.contains("upgrade at"),
        "{community}"
    );
    assert!(
        community.contains("the latest rules the moment they clear QA"),
        "{community}"
    );

    let env = refusal(tid, Source::Env, &Answer::Public(None));
    assert!(
        env.contains("ISOTOPE13_TOKEN") && env.contains("whole token"),
        "{env}"
    );
    let saved = refusal(tid, Source::File, &Answer::Public(None));
    assert!(
        saved.contains("isotope13-api.json") && saved.contains("disconnected"),
        "{saved}"
    );
    let issued = refusal(tid, Source::Device, &Answer::Public(None));
    assert!(issued.contains("just issued"), "{issued}");
    // Nothing is pasted any more, so nothing says to check a paste.
    for message in [&community, &env, &saved, &issued] {
        assert!(!message.contains("pasted"), "{message}");
        assert!(message.contains(tid), "{message}");
    }

    let status = refusal(tid, Source::Env, &Answer::Status("HTTP 401".into()));
    assert!(
        status.contains("(HTTP 401)") && status.contains(crate::enriched::DASH_URL),
        "{status}"
    );
}

#[test]
fn only_the_enriched_channel_sends_a_token() {
    let public = Channel::Public;
    assert_eq!(public.base(), BASE_URL);
    assert_eq!(public.token(), None);

    let token = crate::enriched::Token::parse("i13_krypton85_abc").unwrap();
    let enriched = Channel::Enriched(token.clone());
    assert_eq!(enriched.base(), ENRICHED_URL);
    assert_eq!(enriched.token(), Some(&token));
}

#[test]
fn only_failures_that_could_answer_differently_are_retried() {
    let at = |status| FetchError {
        status: Some(status),
        message: String::new(),
    };
    // A dropped connection is the commonest thing worth asking again about.
    assert!(
        FetchError {
            status: None,
            message: String::new(),
        }
        .retryable()
    );
    assert!(at(500).retryable());
    assert!(at(503).retryable());
    assert!(at(429).retryable());
    assert!(at(408).retryable());
    // A bundle that is not published stays unpublished however many times
    // we ask, and a refused token is answered with another, not by asking.
    assert!(!at(404).retryable());
    assert!(!at(401).retryable());
    assert!(!at(400).retryable());
}

#[test]
fn backoff_jitter_never_exceeds_its_step() {
    // Full jitter: the wait is somewhere in [0, step), so a fleet that
    // starts together does not come back together.
    for step in [RETRY_BASE, Duration::from_secs(1), RETRY_MAX] {
        let wait = jitter(step);
        assert!(wait < step, "{wait:?} must be under {step:?}");
    }
    // A zero step must not divide by zero.
    assert_eq!(jitter(Duration::ZERO), Duration::ZERO);
}

#[test]
fn a_refused_token_is_told_apart_from_an_outage() {
    let refused = |status| FetchError {
        status: Some(status),
        message: String::new(),
    };
    // A refused token asks for another...
    assert!(refused(401).unauthorized());
    assert!(refused(403).unauthorized());
    // ...but a bucket that is down is an error the operator must see, not
    // a reason to prompt anyone for a token.
    assert!(!refused(404).unauthorized());
    assert!(!refused(500).unauthorized());
    assert!(
        !FetchError {
            status: None,
            message: String::new(),
        }
        .unauthorized()
    );
    assert_eq!(refused(401).status_text(), "HTTP 401");
}

fn staged(root: &Path) -> PathBuf {
    let staging = root.join(".traits-staging");
    std::fs::create_dir_all(staging.join("objectives")).unwrap();
    std::fs::write(staging.join("marker"), "new").unwrap();
    staging
}

#[test]
fn swap_replaces_existing_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("traits");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("stale"), "old").unwrap();

    let staging = staged(tmp.path());
    swap_into_place(&staging, &dir, &tmp.path().join(".traits-backup")).unwrap();

    assert!(dir.join("marker").is_file());
    assert!(!dir.join("stale").exists(), "old tree should be gone");
    assert!(!staging.exists(), "staging should have been moved");
}

#[cfg(unix)]
#[test]
fn swap_replaces_dangling_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("traits");
    std::os::unix::fs::symlink(tmp.path().join("gone"), &dir).unwrap();
    assert!(!dir.exists(), "precondition: the link resolves to nothing");

    let staging = staged(tmp.path());
    swap_into_place(&staging, &dir, &tmp.path().join(".traits-backup")).unwrap();

    assert!(std::fs::symlink_metadata(&dir).unwrap().is_dir());
    assert!(dir.join("marker").is_file());
}

#[test]
fn swap_leaves_no_backup_behind() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("traits");
    let backup = tmp.path().join(".traits-backup");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(backup.join("leftover")).unwrap();

    swap_into_place(&staged(tmp.path()), &dir, &backup).unwrap();

    assert!(
        !backup.exists(),
        "backup should be dropped after a good swap"
    );
}
