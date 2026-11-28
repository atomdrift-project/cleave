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

/// The commit time is the newest entry mtime, as `git archive` stamps every
/// entry with it; compiled rules, which are never installed, do not count.
#[test]
fn a_bundle_reports_when_its_commit_was_made() {
    let tmp = tempfile::tempdir().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    for (path, mtime) in [
        ("metadata/a.yaml", 1_763_500_000),
        ("metadata/b.yaml", 1_763_456_789),
        ("third-party/compiled/php.yrc", 1_999_999_999),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_mtime(mtime);
        header.set_cksum();
        builder
            .append_data(&mut header, path, b"x".as_slice())
            .unwrap();
    }
    let archive = builder.into_inner().unwrap();
    let committed = unpack_bundle(Cursor::new(archive), tmp.path(), false).unwrap();
    assert_eq!(committed, Some(1_763_500_000));
}

/// An older sidecar, with only a date, answers with that day's last second.
#[test]
fn a_dated_sidecar_is_committed_by_the_end_of_its_day() {
    assert_eq!(end_of_day("1970-01-01"), Some(86_399));
    assert_eq!(end_of_day("2026-11-18"), Some(1_795_046_399));
    assert_eq!(end_of_day("2024-02-29"), Some(1_709_251_199));
    assert_eq!(end_of_day("2026-13-01"), None);
    assert_eq!(end_of_day("soon"), None);

    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(committed_at(tmp.path()), None, "no sidecar, no time");
    let mut meta = Installed {
        commit: "deed861c72b71abcd1803ad685496e377ca52c2e".into(),
        date: "2026-11-18".into(),
        ..Installed::default()
    };
    std::fs::write(tmp.path().join(SIDECAR), toml::to_string(&meta).unwrap()).unwrap();
    assert_eq!(committed_at(tmp.path()), Some(1_795_046_399));
    meta.committed = Some(1_795_000_000);
    std::fs::write(tmp.path().join(SIDECAR), toml::to_string(&meta).unwrap()).unwrap();
    assert_eq!(committed_at(tmp.path()), Some(1_795_000_000));
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
    use crate::feed::{Feed, Source};
    let tid = "8f2d0497b4e2c5a7";
    let refused = |opened: &[Feed], tier: Option<&str>| Answer::Refused {
        opened: opened.to_vec(),
        tier: tier.map(str::to_owned),
    };

    // A supporter plan asking for zero-day is pointed at the feed it has.
    let supporter = refusal(
        tid,
        Source::File,
        Feed::ZeroDay,
        refused(&[Feed::Supporter, Feed::Oss], Some("supporter")),
    );
    let message = &supporter.message;
    assert!(
        message.contains("Supporter plan includes the supporter feed (up to 48 hours after QA)")
            && message.contains("not the zero-day feed (up to 15 minutes)")
            && message.contains("`--feed=supporter`")
            && message.contains("https://console.atomdrift.com/teams#new"),
        "{message}"
    );
    assert_eq!(supporter.opened, [Feed::Supporter, Feed::Oss]);
    assert!(supporter.recognised);

    // Community opens only the open-source feed: upgrade, nothing to switch to.
    let community = refusal(
        tid,
        Source::File,
        Feed::Supporter,
        refused(&[Feed::Oss], Some("free")),
    );
    assert!(
        community.message.contains("Community plan")
            && community.message.contains("includes only the oss feed")
            && community
                .message
                .contains("https://console.atomdrift.org/plans"),
        "{}",
        community.message
    );
    assert!(community.recognised);

    let env = refusal(tid, Source::Env, Feed::ZeroDay, refused(&[Feed::Oss], None));
    assert!(
        env.message.contains(crate::feed::token_env()) && env.message.contains("whole token"),
        "{}",
        env.message
    );
    assert!(
        !env.recognised,
        "an unknown token says nothing about a plan"
    );
    let saved = refusal(tid, Source::File, Feed::ZeroDay, refused(&[], None));
    assert!(
        saved.message.contains("expired or was revoked") && saved.message.contains(" login`"),
        "{}",
        saved.message
    );
    let issued = refusal(tid, Source::Device, Feed::ZeroDay, refused(&[], None));
    assert!(issued.message.contains("just issued"), "{}", issued.message);
    // Where the token itself is the problem, it is named as the console
    // names it.
    for refusal in [&env, &saved, &issued] {
        assert!(refusal.message.contains(tid), "{}", refusal.message);
    }
    // Plain words, under Atomdrift's name: no vendor host, no file path. The
    // variable a CI job sets is named as it is spelled.
    for refusal in [&supporter, &community, &env, &saved, &issued] {
        let message = refusal
            .message
            .replace(crate::feed::token_env(), "")
            .to_lowercase();
        for word in ["uplink", "isotope13", ".json"] {
            assert!(!message.contains(word), "{message}");
        }
    }

    let status = refusal(
        tid,
        Source::Env,
        Feed::ZeroDay,
        Answer::Status("HTTP 401".into()),
    );
    assert!(
        status.message.contains("HTTP 401)") && status.message.contains("zero-day feed"),
        "{}",
        status.message
    );
    assert!(status.opened.is_empty() && !status.recognised);
}

#[test]
fn only_paid_feeds_send_a_token_and_each_has_its_own_base() {
    use crate::feed::Feed;
    let public = Channel::Public;
    assert_eq!(public.base(), BASE_URL);
    assert_eq!(public.token(), None);
    assert_eq!(public.feed(), Feed::Oss);

    let token = crate::feed::Token::parse("i13_krypton85_abc").unwrap();
    let zero_day = Channel::Paid(Feed::ZeroDay, token.clone());
    assert_eq!(
        zero_day.base(),
        "https://updates.isotope13.ai/v1/rules/cleave/zero-day"
    );
    assert_eq!(zero_day.token(), Some(&token));
    let supporter = Channel::Paid(Feed::Supporter, token);
    assert_eq!(
        supporter.base(),
        "https://updates.isotope13.ai/v1/rules/cleave/supporter"
    );
    assert_eq!(supporter.feed(), Feed::Supporter);
}

#[test]
fn only_failures_that_could_answer_differently_are_retried() {
    let at = |status| FetchError {
        status: Some(status),
        ..FetchError::default()
    };
    // A dropped connection is the commonest thing worth asking again about.
    assert!(FetchError::default().retryable());
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
        ..FetchError::default()
    };
    // A refused token asks for another...
    assert!(refused(401).unauthorized());
    assert!(refused(403).unauthorized());
    // ...but a bucket that is down is an error the operator must see, not
    // a reason to prompt anyone for a token.
    assert!(!refused(404).unauthorized());
    assert!(!refused(500).unauthorized());
    assert!(!FetchError::default().unauthorized());
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
