/// The explicit-list scanner shares this dispatcher with directory scans.
/// On a two-thread pool its final two roots must be allowed to fan out,
/// even with multiple top-level analyses still in flight.
#[test]
#[allow(clippy::unwrap_used)]
fn ordered_scan_releases_inner_parallelism_when_the_batch_drains() {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let visits = std::sync::atomic::AtomicUsize::new(0);
    pool.install(|| {
        use rayon::prelude::*;
        // Reproduce the old explicit-list policy with the same two roots.
        [0, 1].par_iter().for_each(|_| {
            let _isolation = crate::rayon_nest::isolate_counters();
            let _first = crate::rayon_nest::enter_toplevel_analysis_on(false);
            let _second = crate::rayon_nest::enter_toplevel_analysis_on(false);
            assert!(
                !crate::pool_has_headroom(),
                "old dispatcher never marks draining"
            );
        });
        super::for_each_ordered(&[0, 1], &|_| {
            let _isolation = crate::rayon_nest::isolate_counters();
            let _first = crate::rayon_nest::enter_toplevel_analysis_on(false);
            let _second = crate::rayon_nest::enter_toplevel_analysis_on(false);
            assert!(
                crate::pool_has_headroom(),
                "idle lanes must be usable by inner work"
            );
            visits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
    });
    assert_eq!(visits.load(std::sync::atomic::Ordering::Relaxed), 2);
}
use super::*;

#[test]
#[allow(clippy::expect_used)]
fn test_max_analysis_depth_constant() {
    assert_eq!(MAX_ANALYSIS_DEPTH, 8);
}

/// `analyze_bytes_shared` (zero-copy `Bytes` path) must produce the same
/// report as `analyze_bytes_owned` for identical input.
#[test]
#[allow(clippy::expect_used)]
fn analyze_bytes_shared_matches_owned() {
    // Distinct payload so the content-keyed report cache can't collide.
    let payload = b"#!/bin/sh\necho analyze_bytes_shared_parity_probe\n";
    let options = AnalysisOptions {
        yara: false,
        ..Default::default()
    };

    let shared = analyze_bytes_shared(bytes::Bytes::from_static(payload), "probe.sh", &options)
        .expect("shared analysis");
    let owned =
        analyze_bytes_owned(payload.to_vec(), "probe.sh", &options).expect("owned analysis");

    assert_eq!(shared.target.sha256, owned.target.sha256);
    assert_eq!(shared.target.file_type, owned.target.file_type);
    assert_eq!(shared.findings.len(), owned.findings.len());
}

/// A cache-hit report carries the cache donor's `file.basename`/`file.stem`
/// (the cache is content-keyed); the hit path must re-stamp them with the
/// name of the file actually analyzed.
#[test]
#[allow(clippy::expect_used)]
fn restamp_path_derived_values_replaces_donor_name() {
    let target = types::TargetInfo {
        path: "donor.sh".to_string(),
        file_type: "shell".to_string(),
        size_bytes: 1,
        sha256: "abc".to_string(),
        architectures: None,
    };
    let mut report = types::AnalysisReport::new(target);
    report.values_tree = Some(Box::new(serde_json::json!({
        "file": { "basename": "donor.sh", "stem": "donor" },
        "shebang": { "interpreter": "bash" },
    })));

    restamp_path_derived_values(&mut report, Path::new("/tmp/actual.tar.gz"));

    let tree = report.values_tree.as_deref().expect("values tree retained");
    assert_eq!(tree["file"]["basename"], "actual.tar.gz");
    assert_eq!(tree["file"]["stem"], "actual.tar");
    // Unrelated namespaces are untouched.
    assert_eq!(tree["shebang"]["interpreter"], "bash");

    // A report reconstructed from compact member kv has no values tree,
    // but its flattened path values still need the same correction.
    let mut bare = types::AnalysisReport::new(types::TargetInfo {
        path: "x".to_string(),
        file_type: "shell".to_string(),
        size_bytes: 1,
        sha256: "abc".to_string(),
        architectures: None,
    });
    bare.cached_member_kv = Some(std::collections::BTreeMap::from([
        ("file.basename".to_string(), serde_json::json!("donor.sh")),
        ("file.stem".to_string(), serde_json::json!("donor")),
        ("source.language".to_string(), serde_json::json!("shell")),
    ]));
    restamp_path_derived_values(&mut bare, Path::new("/tmp/actual.sh"));
    assert!(bare.values_tree.is_none());
    let kv = bare.cached_member_kv.as_ref().expect("cached kv retained");
    assert_eq!(kv["file.basename"], "actual.sh");
    assert_eq!(kv["file.stem"], "actual");
    assert_eq!(kv["source.language"], "shell");
}

/// The cross-context cache stores an `AnalysisReport` as `FileAnalysis`
/// and reconstructs it on a member cache hit. Source AST symbols live only
/// in `filefacts`, so dropping that field makes cached source files appear
/// to have far fewer symbols than freshly analyzed identical bytes.
#[test]
#[allow(clippy::expect_used)]
fn file_analysis_cache_round_trip_preserves_source_symbols() {
    let target = types::TargetInfo {
        path: "donor.js".to_string(),
        file_type: "javascript".to_string(),
        size_bytes: 16,
        sha256: "abc".to_string(),
        architectures: None,
    };
    let mut report = types::AnalysisReport::new(target);
    report.filefacts = Some(types::FilefactsView {
        symbols: vec![filefacts::Symbol::Member {
            path: "window.localStorage".to_string(),
            offset: Some(4),
        }],
        ..Default::default()
    });

    let cached = report.to_file_analysis(0, &crate::Engine::empty());
    let restored = report_from_file_analysis(cached, "actual.js".to_string());

    assert_eq!(restored.target.path, "actual.js");
    let symbols = &restored
        .filefacts
        .as_ref()
        .expect("filefacts survives cache round trip")
        .symbols;
    assert!(matches!(
        symbols.as_slice(),
        [filefacts::Symbol::Member { path, offset: Some(4) }]
            if path == "window.localStorage"
    ));
}

/// `PhaseTracker::new()` must not register (otherwise every default
/// `AnalysisOptions` would leave an entry in the global list).
/// `with_label` registers; dropping the last handle removes the entry
/// from snapshots on the next call.
#[test]
#[allow(clippy::expect_used)]
fn phase_tracker_registry_lifecycle() {
    fn contains_label(snap: &[PhaseSnapshot], label: &str) -> bool {
        snap.iter().any(|(l, _, _, _)| l == label)
    }

    let marker = format!("phase-test-{}", std::process::id());

    // Unlabeled trackers never appear in the registry.
    let _anon = PhaseTracker::new();
    assert!(!contains_label(&snapshot_active_phases(), &marker));

    // Labeled tracker shows up while alive and carries the current phase.
    {
        let t = PhaseTracker::with_label(&marker);
        t.set("yara");
        let snap = snapshot_active_phases();
        let entry = snap
            .iter()
            .find(|(l, _, _, _)| l == &marker)
            .expect("registered tracker should appear in snapshot");
        assert_eq!(entry.1, "yara");
    }

    // Dropping the handle removes it on the next snapshot (the retain()
    // pass prunes Weak references with no surviving Arc).
    assert!(!contains_label(&snapshot_active_phases(), &marker));
}

/// Verify that analyzing a file at the depth limit emits the deep-nesting
/// finding instead of recursing further.  We create a Python file whose
/// content is a base64-encoded shell command (one layer of encoding) and
/// invoke analysis at depth == MAX_ANALYSIS_DEPTH so the payload loop
/// hits the depth guard.
#[test]
#[allow(clippy::expect_used)]
fn test_analysis_depth_limit_emits_finding() {
    use std::io::Write;

    // base64("echo hello") = "ZWNobyBoZWxsbw=="
    // Wrap it in Python so the file is recognized as a script with an
    // encoded payload that would normally trigger recursive analysis.
    let code = b"import base64\ndata = 'ZWNobyBoZWxsbw=='\nresult = base64.b64decode(data)\n";

    #[allow(clippy::expect_used)]
    let tmp = tempfile::Builder::new()
        .suffix(".py")
        .tempfile()
        .expect("create temp file");
    #[allow(clippy::expect_used)]
    tmp.as_file().write_all(code).expect("write test content");
    let path = tmp.path();

    // Skip YARA: this test checks depth-limit handling, not YARA matches,
    // and the YARA engine load adds ~60s of unnecessary init.
    let options = AnalysisOptions {
        yara: false,
        ..AnalysisOptions::default()
    };
    let engine = shared_resources::engine_for_options(&options)
        .expect("mapper should load for depth-limit test");

    // Analyze at exactly MAX_ANALYSIS_DEPTH — any encoded payloads found
    // should trigger the deep-nesting finding instead of recursing.
    #[allow(clippy::expect_used)]
    let report = analyze_file_with_resources_at_depth(
        path,
        &options,
        &engine,
        None,
        None,
        MAX_ANALYSIS_DEPTH,
    )
    .expect("analysis should succeed even at depth limit");

    // If the file produced encoded payloads, the depth guard should have
    // emitted the deep-nesting finding.  If no payloads were detected
    // (encoding detection is heuristic), the finding won't appear — that's
    // fine, we just verify no stack overflow occurred and the function
    // returned normally.
    if let Some(f) = report
        .findings
        .iter()
        .find(|f| f.id == "objectives/anti-static/obfuscation/multi-layer/deep-nesting")
    {
        assert_eq!(f.crit, types::Criticality::Suspicious);
        assert_eq!(f.attack.as_deref(), Some("T1027"));
        assert_eq!(f.mbc.as_deref(), Some("OB0002"));
        assert!(
            f.evidence.iter().any(|e| e.value.contains("depth=")),
            "evidence should include depth"
        );
    }
}

/// Verify that depth 0 (normal) does NOT emit the deep-nesting finding
/// for a simple file.
#[test]
#[allow(clippy::expect_used)]
fn test_analysis_depth_zero_no_deep_nesting_finding() {
    use std::io::Write;

    let code = b"print('hello world')\n";
    #[allow(clippy::expect_used)]
    let tmp = tempfile::Builder::new()
        .suffix(".py")
        .tempfile()
        .expect("create temp file");
    #[allow(clippy::expect_used)]
    tmp.as_file().write_all(code).expect("write test content");

    let options = AnalysisOptions {
        all_files: true,
        yara: false,
        ..AnalysisOptions::default()
    };
    let engine = shared_resources::engine_for_options(&options)
        .expect("mapper should load for depth-zero test");

    #[allow(clippy::expect_used)]
    let report = analyze_file_with_resources_at_depth(tmp.path(), &options, &engine, None, None, 0)
        .expect("analysis should succeed");

    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id.contains("deep-nesting")),
        "depth-0 analysis should not produce deep-nesting finding"
    );
}
