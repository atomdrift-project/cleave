#[test]
fn isolated_owner_can_publish_to_a_single_scan_worker() {
    use std::sync::mpsc::sync_channel;
    use std::time::Duration;
    let sha = "isolated-leaf-owner-single-worker";
    let options = AnalysisOptions::default();
    let settings = settings_of(&options);
    let (ready_tx, ready_rx) = sync_channel(0);
    let (release_tx, release_rx) = sync_channel(0);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let owner = acquire_member_flight(sha, "javascript", &options, &settings);
            let owner_ref = &owner;
            crate::rayon_nest::with_isolated_leaf_pool(2, move || {
                owner_ref.mark_isolated_owner();
                ready_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
            owner.complete(Some(&test_report(sha)));
        });
        ready_rx.recv().unwrap();
        let follower = acquire_member_flight(sha, "javascript", &options, &settings);
        assert!(follower.can_wait_for_isolated_owner());
        crate::rayon_nest::with_isolated_leaf_pool(2, || {
            assert!(
                !follower.can_wait_for_isolated_owner(),
                "private pools must never wait for each other"
            );
            let _nested = crate::rayon_nest::enter_toplevel_analysis_on(false);
            assert!(
                !follower.can_wait_for_isolated_owner(),
                "nested options must not erase the exclusive worker's wait restriction"
            );
        });
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(|| {
                assert!(follower.wait_isolated(Duration::ZERO).is_none());
                release_tx.send(()).unwrap();
                let report = follower
                    .wait_isolated(Duration::from_secs(10))
                    .unwrap()
                    .unwrap();
                assert_eq!(report.target.sha256, sha);
            });
    });
}

#[test]
fn a_dedicated_archive_pool_is_not_an_isolated_leaf() {
    let options = AnalysisOptions::default();
    let settings = settings_of(&options);
    let owner = acquire_member_flight("dedicated-not-isolated", "javascript", &options, &settings);
    let _guard = crate::rayon_nest::enter_toplevel_analysis_on(true);
    owner.mark_isolated_owner();
    assert!(!owner.state.isolated_owner.load(Ordering::Acquire));
}

/// The settings an `AnalysisOptions` free function keys its cache entries with.
fn settings_of(options: &AnalysisOptions) -> Settings {
    crate::shared_resources::settings_for_options(options)
}

/// An engine's entries are keyed on what the engine was built with: the
/// engine-level fields of a call's options cannot file a report under a
/// configuration that did not produce it, and member folding separates
/// entries because it changes what a report retains.
#[test]
fn key_follows_engine_settings_not_call_options() {
    let settings = Settings::default();
    let a = AnalysisOptions::default();
    let b = AnalysisOptions {
        third_party_yara: !a.third_party_yara,
        upx: !a.upx,
        platforms: vec![crate::composite_rules::Platform::Linux],
        ..AnalysisOptions::default()
    };
    assert_eq!(options_hash(&a, &settings), options_hash(&b, &settings));

    let compact = Settings {
        compact_members: true,
        ..Settings::default()
    };
    assert_ne!(options_hash(&a, &settings), options_hash(&a, &compact));
    let no_upx = Settings {
        upx: false,
        ..Settings::default()
    };
    assert_ne!(options_hash(&a, &settings), options_hash(&a, &no_upx));
}
use super::*;
use crate::types::FileAnalysis;
use crate::types::core::{AnalysisReport, TargetInfo};

fn report_cache_store_conn(c: &Connection, sha: &str, opts: &str, ts: i64, r: &AnalysisReport) {
    let json = serde_json::to_vec(r).expect("serialize report");
    cache_store_conn(c, memo::Kind::Report, sha, opts, ts, &json);
}

fn report_cache_lookup_conn(
    c: &Connection,
    sha: &str,
    opts: &str,
    ts: i64,
) -> Option<AnalysisReport> {
    let json = cache_lookup_conn(c, memo::Kind::Report, sha, opts, ts)?;
    serde_json::from_slice(&json).ok()
}

fn file_analysis_cache_store_conn(
    c: &Connection,
    sha: &str,
    opts: &str,
    ts: i64,
    fa: &FileAnalysis,
) {
    let json = serde_json::to_vec(fa).expect("serialize file analysis");
    cache_store_conn(c, memo::Kind::FileAnalysis, sha, opts, ts, &json);
}

fn file_analysis_cache_lookup_conn(
    c: &Connection,
    sha: &str,
    opts: &str,
    ts: i64,
) -> Option<FileAnalysis> {
    let json = cache_lookup_conn(c, memo::Kind::FileAnalysis, sha, opts, ts)?;
    serde_json::from_slice(&json).ok()
}

/// Every input that changes a report is part of its cache key: the YARA
/// overrides outside `AnalysisOptions`, and the zip passwords.
#[test]
fn options_hash_covers_yara_overrides_and_zip_passwords() {
    use crate::yara_engine::YaraOverrides;
    let options = AnalysisOptions::default();
    let base = options_hash_with(&options, &settings_of(&options), YaraOverrides::default());
    assert_eq!(
        base,
        options_hash_with(&options, &settings_of(&options), YaraOverrides::default())
    );
    let skip = YaraOverrides {
        skip: true,
        ..Default::default()
    };
    let builtin_only = YaraOverrides {
        builtin_only: true,
        ..Default::default()
    };
    assert_ne!(
        base,
        options_hash_with(&options, &settings_of(&options), skip)
    );
    assert_ne!(
        base,
        options_hash_with(&options, &settings_of(&options), builtin_only)
    );
    let mut with_password = options.clone();
    with_password.zip_passwords.push("hunter2".to_string());
    assert_ne!(
        base,
        options_hash_with(
            &with_password,
            &settings_of(&with_password),
            YaraOverrides::default()
        )
    );
}

fn test_report(sha256: &str) -> AnalysisReport {
    let target = TargetInfo {
        path: "/test/sample.bin".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: sha256.to_string(),
        architectures: None,
    };
    AnalysisReport::new(target)
}

/// A store must key on the traits the analysis actually ran under, not on
/// whatever the process-global traits scan holds by the time it finishes.
///
/// `reload_capability_mapper` — scan's
/// periodic renewal task — drops the memoized traits fingerprint and
/// installs a new mapper while analyses are still in flight. Keying the
/// store on the ambient fingerprint filed a report evaluated against the
/// OLD rules under the NEW rules' revision, so every later scan of that
/// file was served a pre-update verdict: precisely the staleness the
/// reload's own invalidation exists to prevent, and a detection miss when
/// the update is what added the rule.
///
/// Deliberately does not switch the traits override to produce the second
/// revision: that is process-global state, and mutating it here would
/// corrupt every sibling test sharing this process. Passing a revision
/// that differs from the ambient one models the same thing — an analysis
/// that ran under a tree the process is no longer pointing at.
#[test]
fn byte_identical_twins_keep_their_own_rows() {
    let sha = "7a1c0e0e00000000000000000000000000000000000000000000000000000000";
    let opts = AnalysisOptions::default();
    let revision = ambient_traits_revision();
    let (cmd, bat) = (
        std::path::Path::new("/t/sample.cmd"),
        std::path::Path::new("/t/sample.bat"),
    );
    let key_cmd = report_type_key("batch", cmd);
    let key_bat = report_type_key("batch", bat);
    assert_ne!(key_cmd, key_bat);
    assert_ne!(
        report_type_key("zip", std::path::Path::new("/t/a.zip")),
        report_type_key("zip", std::path::Path::new("/t/b.zip"))
    );
    // Same name in another directory: one row, left to the path guard.
    assert_eq!(
        key_cmd,
        report_type_key("batch", std::path::Path::new("/u/sample.cmd"))
    );

    let mut for_cmd = test_report(sha);
    for_cmd.target.path = "/t/sample.cmd".into();
    let mut for_bat = test_report(sha);
    for_bat.target.path = "/t/sample.bat".into();
    report_cache_store(
        sha,
        &key_cmd,
        &opts,
        &settings_of(&opts),
        &for_cmd,
        revision,
    );
    report_cache_store(
        sha,
        &key_bat,
        &opts,
        &settings_of(&opts),
        &for_bat,
        revision,
    );

    let got_cmd = report_cache_lookup(
        sha,
        &key_cmd,
        &opts,
        &settings_of(&opts),
        "/t/sample.cmd",
        None,
    );
    let got_bat = report_cache_lookup(
        sha,
        &key_bat,
        &opts,
        &settings_of(&opts),
        "/t/sample.bat",
        None,
    );
    assert_eq!(
        got_cmd.map(|r| r.target.path).as_deref(),
        Some("/t/sample.cmd")
    );
    assert_eq!(
        got_bat.map(|r| r.target.path).as_deref(),
        Some("/t/sample.bat")
    );
}

/// A report whose rule evaluation ran out of time, or whose source parse
/// was cut short, lacks results a later run
/// would have, so it must not be served to later runs — nor a container
/// holding such a member.
#[test]
fn incomplete_reports_are_not_cached() {
    use crate::types::AnalysisGap::{EvaluationDeadline, SourceParseIncomplete};
    let opts = AnalysisOptions::default();
    let settings = settings_of(&opts);
    let revision = ambient_traits_revision();
    let lookup = |sha: &str, report: &AnalysisReport| {
        report_cache_lookup(sha, "elf", &opts, &settings, &report.target.path, None)
    };

    for (n, gap) in [EvaluationDeadline, SourceParseIncomplete]
        .into_iter()
        .enumerate()
    {
        let sha = format!("6e1d00de{:056x}", 2 * n + 1);
        let cut_short = test_report(&sha);
        cut_short.analysis_gaps.record(gap);
        report_cache_store(&sha, "elf", &opts, &settings, &cut_short, revision);
        assert!(lookup(&sha, &cut_short).is_none(), "{gap:?}");

        let sha = format!("6e1d00de{:056x}", 2 * n + 2);
        let mut container = test_report(&sha);
        let member = FileAnalysis::new(1, "a.zip!!x.so".into(), "elf".into(), sha.clone(), 1);
        member.analysis_gaps.record(gap);
        container.files.push(member);
        report_cache_store(&sha, "elf", &opts, &settings, &container, revision);
        assert!(lookup(&sha, &container).is_none(), "member {gap:?}");
    }

    // Control: the same report without a gap is cached.
    let sha = format!("6e1d00de{:056x}", 99);
    let complete = test_report(&sha);
    report_cache_store(&sha, "elf", &opts, &settings, &complete, revision);
    assert!(lookup(&sha, &complete).is_some());
}

#[test]
fn store_keys_on_the_traits_the_analysis_ran_under() {
    let ambient = ambient_traits_revision();
    // The mapper this analysis held was built from a different tree.
    let ran_under = ambient.wrapping_add(1);

    let sha = "5d7b1f0e00000000000000000000000000000000000000000000000000000000";
    let opts = AnalysisOptions::default();
    report_cache_store(
        sha,
        "elf",
        &opts,
        &settings_of(&opts),
        &test_report(sha),
        ran_under,
    );

    assert!(
        report_cache_lookup(
            sha,
            "elf",
            &opts,
            &settings_of(&opts),
            "/test/sample.bin",
            None
        )
        .is_none(),
        "a report evaluated under the pre-reload traits was served to a \
             caller running the post-reload traits"
    );
}

fn test_conn() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory SQLite must succeed in test");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS toplevel_report_cache (
                sha256 TEXT NOT NULL,
                options_hash TEXT NOT NULL,
                traits_timestamp INTEGER NOT NULL,
                report BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                PRIMARY KEY (sha256, options_hash, traits_timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_toplevel_report_last_accessed
                ON toplevel_report_cache(last_accessed);",
    )
    .expect("table creation must succeed in test");
    conn
}

/// In-memory connection with the file_cache table (for testing file_cache_*_conn).
fn file_analysis_test_conn() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory SQLite must succeed in test");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS file_analysis_cache (
                sha256 TEXT NOT NULL,
                options_hash TEXT NOT NULL,
                traits_timestamp INTEGER NOT NULL,
                file_analysis BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                PRIMARY KEY (sha256, options_hash, traits_timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_file_analysis_last_accessed
                ON file_analysis_cache(last_accessed);",
    )
    .expect("file_cache table creation must succeed in test");
    conn
}

fn test_file_analysis(sha256: &str, file_type: &str) -> FileAnalysis {
    FileAnalysis::new(
        0,
        "pkg/source.js".to_string(),
        file_type.to_string(),
        sha256.to_string(),
        512,
    )
}

#[test]
fn cached_negative_results_require_an_origin() {
    let mut file = test_file_analysis("path-origin", "rust");
    file.path.clear();
    assert!(cached_file_under(file.clone(), "build.rs", None).is_none());
    file.path = "build.rs".to_string();
    assert!(cached_file_under(file, "build.rs", None).is_some());

    let mut report = test_report("path-origin");
    report.target.path.clear();
    assert!(cached_report_under(report.clone(), "build.rs", None).is_none());
    report.target.path = "build.rs".to_string();
    assert!(cached_report_under(report, "build.rs", None).is_some());
}

#[test]
fn file_cache_rejects_archive_roots_even_without_retained_members() {
    let options = AnalysisOptions::default();
    for kind in ["zip", "tar", "npm", "whl", "jar", "python_sdist"] {
        let mut report = test_report("archive-leaf-cache-regression");
        report.target.file_type = kind.to_string();
        assert!(archive_file_type(kind), "{kind}");
        assert!(!complete_leaf_report(&report), "{kind}");
        // Reject before consulting either the process memo or SQLite.
        assert!(
            file_analysis_cache_lookup(
                &report.target.sha256,
                kind,
                &options,
                &settings_of(&options),
                &report.target.path,
                None
            )
            .is_none()
        );
    }
}

#[test]
fn file_cache_rejects_lossy_decoded_tree_projection() {
    let mut report = test_report("decoded-tree-cache-regression");
    report.target.file_type = "javascript".to_string();
    report
        .files
        .push(test_file_analysis("decoded-child", "javascript"));
    let projected = report.to_file_analysis(0, &crate::Engine::empty());
    let restored = crate::report_from_file_analysis(projected, "loader.js".to_string());
    // This is the lossy representation the old secondary cache accepted.
    assert_eq!(report.files.len(), 1);
    assert!(restored.files.is_empty());
    assert!(!complete_leaf_report(&report));

    report.files.clear();
    report
        .archive_contents
        .push(crate::types::ArchiveEntry::default());
    assert!(!complete_leaf_report(&report));
    report.archive_contents.clear();
    assert!(complete_leaf_report(&report));
}

#[test]
fn full_report_cache_preserves_children_when_leaf_projection_is_rejected() {
    let conn = test_conn();
    let mut report = test_report("full-tree-cache-regression");
    report.target.file_type = "zip".to_string();
    report.files.push(test_file_analysis("member-sha", "php"));
    report.archive_contents.push(crate::types::ArchiveEntry {
        path: "plugin/main.php".to_string(),
        ..Default::default()
    });
    assert!(!complete_leaf_report(&report));
    report_cache_store_conn(&conn, &report.target.sha256, "opts", 1, &report);
    let restored = report_cache_lookup_conn(&conn, &report.target.sha256, "opts", 1)
        .expect("full report cache hit");
    assert_eq!(restored.files.len(), 1);
    assert_eq!(restored.files[0].sha256, "member-sha");
    assert_eq!(restored.archive_contents[0].path, "plugin/main.php");
}

#[test]
fn has_reports_is_per_revision() {
    let conn = test_conn();
    assert!(!has_reports_conn(&conn, 1));
    let report = test_report("revision-presence");
    report_cache_store_conn(&conn, &report.target.sha256, "opts", 1, &report);
    assert!(has_reports_conn(&conn, 1));
    assert!(!has_reports_conn(&conn, 2));
}

#[test]
fn report_flight_shares_one_completed_report() {
    let sha = "single-flight-regression-unique";
    let options = AnalysisOptions::default();
    let owner = acquire_report_flight(sha, "python", &options, &settings_of(&options));
    assert!(owner.is_owner());

    let follower = acquire_report_flight(sha, "python", &options, &settings_of(&options));
    assert!(!follower.is_owner());

    let report = test_report(sha);
    owner.complete(Some(&report));

    let shared = follower.wait().expect("follower should receive report");
    assert_eq!(shared.target.sha256, sha);
    assert_eq!(shared.target.file_type, "elf");
}

#[test]
fn completed_flights_preserve_waiters_across_generations() {
    let sha = "flight-generation-regression-unique";
    let options = AnalysisOptions::default();
    let settings = settings_of(&options);
    let first = acquire_report_flight(sha, "python", &options, &settings);
    let first_waiter = acquire_report_flight(sha, "python", &options, &settings);
    let mut first_report = test_report(sha);
    first_report.target.path = "first.py".to_string();
    first.complete(Some(&first_report));

    let second = acquire_report_flight(sha, "python", &options, &settings);
    assert!(second.is_owner());
    let second_waiter = acquire_report_flight(sha, "python", &options, &settings);
    let mut second_report = test_report(sha);
    second_report.target.path = "second.py".to_string();
    second.complete(Some(&second_report));

    assert_eq!(first_waiter.wait().unwrap().target.path, "first.py");
    assert_eq!(second_waiter.wait().unwrap().target.path, "second.py");
}

#[test]
fn independent_fallback_releases_observer_before_owner_completion() {
    let sha = "independent-observer-release-regression";
    let options = AnalysisOptions::default();
    let settings = settings_of(&options);
    let owner = acquire_member_flight(sha, "python", &options, &settings);
    let observer = acquire_member_flight(sha, "python", &options, &settings);
    assert!(owner.is_owner());
    assert!(!observer.is_owner());
    let weak = Arc::downgrade(&owner.state);
    observer.run_independently(|| {
        assert_eq!(
            weak.strong_count(),
            1,
            "unused observer must be gone before fallback work"
        );
        owner.complete(Some(&test_report(sha)));
        assert!(
            weak.upgrade().is_none(),
            "fallback must not retain the owner's report"
        );
    });
}

#[test]
fn independent_fallback_preserves_real_waiters() {
    let sha = "independent-observer-keeps-real-waiter";
    let options = AnalysisOptions::default();
    let settings = settings_of(&options);
    let owner = acquire_member_flight(sha, "python", &options, &settings);
    let observer = acquire_member_flight(sha, "python", &options, &settings);
    let waiter = acquire_member_flight(sha, "python", &options, &settings);
    assert!(!observer.is_owner());
    assert!(!waiter.is_owner());
    observer.run_independently(|| owner.complete(Some(&test_report(sha))));
    assert_eq!(
        waiter
            .wait()
            .expect("real waiter receives owner result")
            .target
            .sha256,
        sha
    );
}

#[test]
fn owner_only_completion_releases_the_member_slot() {
    let sha = "unobserved-member-regression-unique";
    let options = AnalysisOptions::default();
    let settings = settings_of(&options);
    let owner = acquire_member_flight(sha, "python", &options, &settings);
    assert!(owner.is_owner());
    let owned_before = OWNED_FLIGHTS.with(std::cell::Cell::get);
    owner.complete(Some(&test_report(sha)));
    assert_eq!(OWNED_FLIGHTS.with(std::cell::Cell::get), owned_before - 1);

    let next = acquire_member_flight(sha, "python", &options, &settings);
    assert!(
        next.is_owner(),
        "a retired flight must not strand a later caller"
    );
    let follower = acquire_member_flight(sha, "python", &options, &settings);
    next.complete(Some(&test_report(sha)));
    assert_eq!(follower.wait().unwrap().target.sha256, sha);
    assert_eq!(OWNED_FLIGHTS.with(std::cell::Cell::get), owned_before - 1);
}

#[test]
fn report_flights_deduplicate_members_without_merging_hashes() {
    let options = AnalysisOptions::default();
    let first = acquire_member_flight("member-sha-a", "python", &options, &settings_of(&options));
    let second = acquire_member_flight("member-sha-b", "python", &options, &settings_of(&options));
    let archive_peer =
        acquire_member_flight("member-sha-a", "python", &options, &settings_of(&options));

    assert!(first.is_owner(), "first member hash owns its analysis");
    assert!(
        second.is_owner(),
        "a different member hash analyzes independently"
    );
    assert!(
        !archive_peer.is_owner(),
        "same member hash joins the flight"
    );

    let report_a = test_report("member-sha-a");
    let report_b = test_report("member-sha-b");
    first.complete(Some(&report_a));
    second.complete(Some(&report_b));

    assert_eq!(archive_peer.wait().unwrap().target.sha256, "member-sha-a");
}

#[test]
fn member_flights_do_not_merge_different_detected_types() {
    let options = AnalysisOptions::default();
    let html = acquire_member_flight("same-member-sha", "html", &options, &settings_of(&options));
    let unknown = acquire_member_flight(
        "same-member-sha",
        "unknown",
        &options,
        &settings_of(&options),
    );

    assert!(html.is_owner());
    assert!(
        unknown.is_owner(),
        "path-dependent file types require independent analysis"
    );
}

#[test]
fn report_flight_shares_member_analysis_between_concurrent_archives() {
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;

    let options = AnalysisOptions::default();
    let owner = acquire_member_flight(
        "shared-member-sha",
        "python",
        &options,
        &settings_of(&options),
    );
    assert!(owner.is_owner());

    let barrier = Arc::new(Barrier::new(2));
    let (tx, rx) = mpsc::channel();
    thread::scope(|scope| {
        let barrier_for_archive = Arc::clone(&barrier);
        let options_for_archive = options.clone();
        scope.spawn(move || {
            let archive_peer = acquire_member_flight(
                "shared-member-sha",
                "python",
                &options_for_archive,
                &settings_of(&options_for_archive),
            );
            assert!(!archive_peer.is_owner());
            barrier_for_archive.wait();
            tx.send(archive_peer.wait().map(|report| report.target.sha256))
                .unwrap();
        });

        barrier.wait();
        owner.complete(Some(&test_report("shared-member-sha")));
        assert_eq!(rx.recv().unwrap().as_deref(), Some("shared-member-sha"));
    });
}

#[test]
fn report_flight_wait_never_blocks_nested_rayon_work() {
    use std::sync::{Arc, Barrier};

    // Reproduce the diff/archive cycle that hung node-ipc:
    //
    // * one pool worker owns analysis of a shared member and enters a
    //   nested Rayon join;
    // * the other worker reaches the same SHA and waits as a follower;
    // * the owner's second nested job cannot run if the follower parks.
    //
    // A blocking Condvar wait deadlocks this two-thread pool. The follower
    // instead receives None immediately and leaves the worker available,
    // allowing the owner's nested join to finish.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .expect("build two-thread regression pool");
    let ready = Arc::new(Barrier::new(2));
    let nested = Arc::new(Barrier::new(2));
    let options = AnalysisOptions::default();
    let sha = "member-flight-nested-rayon-regression";

    let avoided_wait = pool.install(|| {
        let ((), avoided_wait) = rayon::join(
            || {
                let owner = acquire_member_flight(sha, "python", &options, &settings_of(&options));
                assert!(owner.is_owner());
                ready.wait();

                let nested_left = Arc::clone(&nested);
                let nested_right = Arc::clone(&nested);
                rayon::join(|| nested_left.wait(), || nested_right.wait());

                owner.complete(Some(&test_report(sha)));
            },
            || {
                ready.wait();
                let follower =
                    acquire_member_flight(sha, "python", &options, &settings_of(&options));
                assert!(!follower.is_owner());
                follower.wait().map(|report| report.target.sha256)
            },
        );
        avoided_wait
    });

    assert_eq!(avoided_wait, None);
}

#[test]
fn evict_idle_drops_only_entries_past_ttl() {
    let conn = test_conn();
    let now = unix_timestamp();
    // One entry last accessed just past the 30-day TTL, one accessed now.
    conn.execute(
        "INSERT INTO toplevel_report_cache
             (sha256, options_hash, traits_timestamp, report, created_at, last_accessed)
             VALUES ('stale', 'h', 0, x'00', 0, ?1), ('fresh', 'h', 0, x'00', 0, ?2)",
        rusqlite::params![now - MAX_IDLE_SECS - 1, now],
    )
    .expect("insert");

    evict_idle(&conn, "toplevel_report_cache");

    let remaining: Vec<String> = conn
        .prepare("SELECT sha256 FROM toplevel_report_cache")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        remaining,
        vec!["fresh".to_string()],
        "the entry idle past 30d is evicted; the fresh one is kept"
    );
}

#[test]
fn enforce_table_bytes_evicts_least_recently_used_over_cap() {
    let conn = test_conn();
    let now = unix_timestamp();
    // Five 400-byte reports (2000 bytes total), last_accessed oldest→newest.
    for (i, age_days) in [5i64, 4, 3, 2, 1].into_iter().enumerate() {
        conn.execute(
            "INSERT INTO toplevel_report_cache
                 (sha256, options_hash, traits_timestamp, report, created_at, last_accessed)
                 VALUES (?1, 'h', 0, ?2, 0, ?3)",
            rusqlite::params![
                format!("s{i}"),
                vec![0u8; 400],
                now - age_days * 24 * 60 * 60
            ],
        )
        .expect("insert");
    }

    // Cap 1000 → target 900; the mean-size estimate sheds the oldest rows.
    enforce_table_bytes(&conn, "toplevel_report_cache", "report", 1000);

    let remaining: Vec<String> = conn
        .prepare("SELECT sha256 FROM toplevel_report_cache ORDER BY last_accessed")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        remaining,
        vec!["s2".to_string(), "s3".to_string(), "s4".to_string()],
        "the least-recently-used entries are evicted first, newest kept"
    );
}

#[test]
fn test_roundtrip() {
    let conn = test_conn();
    let sha = "abc123def456";
    let opts = "test_opts";
    let ts = 1700000000_i64;
    let report = test_report(sha);

    report_cache_store_conn(&conn, sha, opts, ts, &report);
    let cached = report_cache_lookup_conn(&conn, sha, opts, ts);

    assert!(cached.is_some());
    let cached = cached.expect("cache hit expected");
    assert_eq!(cached.target.sha256, sha);
    assert_eq!(cached.target.file_type, "elf");
    assert_eq!(cached.version, "3.0");
}

/// A cache hit must reproduce the *outputs* a fresh analysis would — not just
/// the report's top-level fields. Several things the outputs are built from
/// are transient and rebuilt only during analysis (which a cache hit skips):
/// context windows (render anchoring, with notes derived from findings), finding `evidence` (compact
/// `spans`), and `composite_sources` (compact `from`). If any such field is
/// dropped by serialization, a cached report renders structurally anchorless.
///
/// This guards the whole class generically: a fixture exercising every such
/// field is round-tripped through the *real* cache store/load, and both the
/// tiny render and the compact JSON must come out byte-identical. A new
/// output-feeding field marked `#[serde(skip)]` will fail this test.
#[test]
fn cache_roundtrip_preserves_rendered_outputs() {
    use crate::types::file_analysis::CompositeSource;
    use crate::types::{ContextLine, Criticality, Evidence, Finding};

    let sha = "feedface00";
    let mut report = test_report(sha);

    let mut fa = test_file_analysis(sha, "python");
    fa.path = "pkg/x.py".to_string();

    // An atomic finding with evidence offsets → compact `spans`.
    let mut atom = Finding::capability("micro/exec".to_string(), "exec call".to_string(), 0.9)
        .with_criticality(Criticality::Suspicious);
    atom.evidence = vec![Evidence {
        method: "raw".to_string(),
        value: "exec(payload)".to_string(),
        offsets: vec![17],
        match_len: Some(13),
        ..Default::default()
    }];

    // A composite → its provenance lives in `composite_sources` (compact `from`).
    let composite = Finding::capability(
        "obj/dropper".to_string(),
        "decode→exec dropper".to_string(),
        0.95,
    )
    .with_criticality(Criticality::Hostile);

    fa.findings = vec![atom, composite];
    // Context windows → render anchoring; the atom's span at 17 labels the second.
    fa.context = vec![
        ContextLine {
            loc: 0,
            line: Some(1),
            col: Some(1),
            data: b"data = decode(B)\n".to_vec(),
        },
        ContextLine {
            loc: 17,
            line: Some(2),
            col: Some(1),
            data: b"exec(payload)".to_vec(),
        },
    ];
    fa.composite_sources.insert(
        "obj/dropper".to_string(),
        vec![CompositeSource {
            file: 0,
            line: Some(2),
            offset: Some(17),
        }],
    );
    report.files = vec![fa];

    let compact = |r: &AnalysisReport| {
        serde_json::to_string(&crate::types::compact::compact_from_files(
            &r.files,
            crate::types::Facts::Full,
        ))
        .expect("compact serialization")
    };
    let tiny_before = crate::output::format_tiny(&report);
    let compact_before = compact(&report);

    // The fixture must actually exercise the transient fields, else the test
    // is vacuous — a cache that drops them would still pass on empty data.
    assert!(
        compact_before.contains("spans"),
        "fixture must produce compact spans (from finding evidence): {compact_before}"
    );
    assert!(
        compact_before.contains("\"from\""),
        "fixture must produce compact `from` (from composite_sources): {compact_before}"
    );
    assert!(
        tiny_before.contains("# S 2:1 exec call"),
        "fixture must anchor a note in the render: {tiny_before:?}"
    );

    // Round-trip through the real cache store/load (zstd + serde, both layers).
    let conn = test_conn();
    report_cache_store_conn(&conn, sha, "opts", 1700000000, &report);
    let restored =
        report_cache_lookup_conn(&conn, sha, "opts", 1700000000).expect("cache hit expected");

    assert_eq!(
        tiny_before,
        crate::output::format_tiny(&restored),
        "render anchoring (context windows) lost across cache round-trip"
    );
    assert_eq!(
        compact_before,
        compact(&restored),
        "compact spans/from lost across cache round-trip"
    );

    // The per-file cache layer serializes the same FileAnalysis the same way.
    let fconn = file_analysis_test_conn();
    file_analysis_cache_store_conn(&fconn, sha, "opts", 1700000000, &report.files[0]);
    let rfa = file_analysis_cache_lookup_conn(&fconn, sha, "opts", 1700000000)
        .expect("file cache hit expected");
    let mut file_restored = test_report(sha);
    file_restored.files = vec![rfa];
    assert_eq!(
        compact_before,
        compact(&file_restored),
        "file-analysis cache layer dropped a rendered-output field"
    );
}

#[test]
fn test_cache_miss_wrong_sha256() {
    let conn = test_conn();
    let opts = "test_opts";
    let ts = 1700000000_i64;

    report_cache_store_conn(&conn, "abc123", opts, ts, &test_report("abc123"));
    assert!(report_cache_lookup_conn(&conn, "different_sha", opts, ts).is_none());
}

#[test]
fn test_cache_miss_wrong_timestamp() {
    let conn = test_conn();
    let sha = "abc123";
    let opts = "test_opts";

    report_cache_store_conn(&conn, sha, opts, 1700000000, &test_report(sha));
    assert!(report_cache_lookup_conn(&conn, sha, opts, 1700000001).is_none());
}

#[test]
fn test_cache_miss_wrong_options() {
    let conn = test_conn();
    let sha = "abc123";
    let ts = 1700000000_i64;

    report_cache_store_conn(&conn, sha, "opts_a", ts, &test_report(sha));
    assert!(report_cache_lookup_conn(&conn, sha, "opts_b", ts).is_none());
}

#[test]
fn test_options_hash_deterministic() {
    let opts = AnalysisOptions::default();
    let h1 = options_hash(&opts, &settings_of(&opts));
    let h2 = options_hash(&opts, &settings_of(&opts));
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 16);
}

#[test]
fn typed_options_hash_separates_path_dependent_file_types() {
    let opts = AnalysisOptions::default();
    assert_ne!(
        typed_options_hash(&opts, &settings_of(&opts), "html"),
        typed_options_hash(&opts, &settings_of(&opts), "unknown")
    );
    assert_eq!(
        typed_options_hash(&opts, &settings_of(&opts), "php"),
        typed_options_hash(&opts, &settings_of(&opts), "php")
    );
}

#[test]
fn test_options_hash_varies_with_options() {
    let opts1 = AnalysisOptions::default();
    let opts2 = AnalysisOptions {
        yara: false,
        ..AnalysisOptions::default()
    };

    assert_ne!(
        options_hash(&opts1, &settings_of(&opts1)),
        options_hash(&opts2, &settings_of(&opts2))
    );
}

#[test]
fn test_store_replaces_existing() {
    let conn = test_conn();
    let sha = "abc123";
    let opts = "test_opts";
    let ts = 1700000000_i64;

    report_cache_store_conn(&conn, sha, opts, ts, &test_report(sha));

    let mut report2 = test_report(sha);
    report2.target.file_type = "pe".to_string();
    report_cache_store_conn(&conn, sha, opts, ts, &report2);

    let cached = report_cache_lookup_conn(&conn, sha, opts, ts).expect("cache hit expected");
    assert_eq!(cached.target.file_type, "pe");
}

// ── file_cache tests ──────────────────────────────────────────────────────

#[test]
fn test_file_cache_roundtrip() {
    let conn = file_analysis_test_conn();
    let sha = "deadbeef01234567";
    let opts = "opts_hash";
    let ts = 1700000000_i64;
    let fa = test_file_analysis(sha, "javascript");

    file_analysis_cache_store_conn(&conn, sha, opts, ts, &fa);
    let cached = file_analysis_cache_lookup_conn(&conn, sha, opts, ts);

    assert!(cached.is_some());
    let cached = cached.expect("file cache hit expected");
    assert_eq!(cached.sha256, sha);
    assert_eq!(cached.file_type, "javascript");
    assert_eq!(cached.size, 512);
    // Even a report with no findings must retain its evaluation origin.
    assert_eq!(cached.path, "pkg/source.js");
}

#[test]
fn test_file_cache_miss_wrong_sha256() {
    let conn = file_analysis_test_conn();
    let opts = "opts_hash";
    let ts = 1700000000_i64;

    file_analysis_cache_store_conn(&conn, "aaa", opts, ts, &test_file_analysis("aaa", "python"));
    assert!(file_analysis_cache_lookup_conn(&conn, "bbb", opts, ts).is_none());
}

#[test]
fn test_file_cache_miss_wrong_timestamp() {
    let conn = file_analysis_test_conn();
    let sha = "aabbcc";
    let opts = "opts_hash";

    file_analysis_cache_store_conn(
        &conn,
        sha,
        opts,
        1700000000,
        &test_file_analysis(sha, "elf"),
    );
    assert!(file_analysis_cache_lookup_conn(&conn, sha, opts, 1700000001).is_none());
}

#[test]
fn test_file_cache_miss_wrong_options() {
    let conn = file_analysis_test_conn();
    let sha = "aabbcc";
    let ts = 1700000000_i64;

    file_analysis_cache_store_conn(&conn, sha, "opts_a", ts, &test_file_analysis(sha, "elf"));
    assert!(file_analysis_cache_lookup_conn(&conn, sha, "opts_b", ts).is_none());
}

#[test]
fn test_file_cache_replaces_existing() {
    let conn = file_analysis_test_conn();
    let sha = "aabbcc";
    let opts = "opts_hash";
    let ts = 1700000000_i64;

    file_analysis_cache_store_conn(&conn, sha, opts, ts, &test_file_analysis(sha, "elf"));

    let mut fa2 = test_file_analysis(sha, "pe");
    fa2.size = 9999;
    file_analysis_cache_store_conn(&conn, sha, opts, ts, &fa2);

    let cached = file_analysis_cache_lookup_conn(&conn, sha, opts, ts).expect("hit expected");
    assert_eq!(cached.file_type, "pe");
    assert_eq!(cached.size, 9999);
}

#[test]
fn test_file_cache_preserves_findings() {
    use crate::types::Criticality;
    use crate::types::traits_findings::Finding;

    let conn = file_analysis_test_conn();
    let sha = "cafebabe";
    let opts = "opts_hash";
    let ts = 1700000000_i64;

    let mut fa = test_file_analysis(sha, "javascript");
    fa.findings.push(
        Finding::capability("exec/shell".to_string(), "Shell execution".to_string(), 0.9)
            .with_criticality(Criticality::Hostile),
    );
    fa.compute_summary();

    file_analysis_cache_store_conn(&conn, sha, opts, ts, &fa);
    let cached = file_analysis_cache_lookup_conn(&conn, sha, opts, ts).expect("hit expected");

    assert_eq!(cached.findings.len(), 1);
    assert_eq!(cached.findings[0].id, "exec/shell");
    // ceil(hostile(120) * conf(0.9)) = 108
    assert_eq!(cached.score, 108);
}

#[test]
fn test_file_cache_independent_of_report_cache() {
    // Storing in file_cache should not affect analysis_cache and vice versa.
    let conn = file_analysis_test_conn();
    let sha = "deadbeef";
    let opts = "opts";
    let ts = 1700000000_i64;

    // Nothing in file_cache yet — lookup should miss
    assert!(file_analysis_cache_lookup_conn(&conn, sha, opts, ts).is_none());

    // Storing a FileAnalysis only populates file_cache
    file_analysis_cache_store_conn(&conn, sha, opts, ts, &test_file_analysis(sha, "python"));
    assert!(file_analysis_cache_lookup_conn(&conn, sha, opts, ts).is_some());

    // The separate analysis_cache table is unaffected (would fail if tables were shared)
    let report_conn = test_conn();
    assert!(report_cache_lookup_conn(&report_conn, sha, opts, ts).is_none());
}

#[test]
fn test_file_cache_options_hash_excludes_cancellation() {
    // The cancellation flag must not affect the cache key — same content should
    // hit regardless of whether the caller has a cancellation token set.
    use std::sync::{Arc, atomic::AtomicBool};

    let opts_without = AnalysisOptions::default();
    let opts_with = AnalysisOptions {
        cancellation: Some(Arc::new(AtomicBool::new(false))),
        ..AnalysisOptions::default()
    };

    assert_eq!(
        options_hash(&opts_without, &settings_of(&opts_without)),
        options_hash(&opts_with, &settings_of(&opts_with))
    );
}
